// Package ca provides a certificate authority for issuing device certificates.
package ca

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"time"

	"github.com/manchtools/power-manage/server/internal/mtls"
)

// CA is a certificate authority that issues device certificates.
type CA struct {
	cert      *x509.Certificate
	key       crypto.Signer
	validity  time.Duration
	trustPool *x509.CertPool // trust bundle for verification (supports CA rotation)
}

// Certificate holds a PEM-encoded certificate and private key.
type Certificate struct {
	CertPEM     []byte
	KeyPEM      []byte
	Fingerprint string
	NotAfter    time.Time
}

// New creates a new CA from PEM-encoded certificate and key files.
func New(certPath, keyPath string, validity time.Duration) (*CA, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read CA certificate: %w", err)
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read CA key: %w", err)
	}

	return NewFromPEM(certPEM, keyPEM, validity)
}

// NewFromPEM creates a new CA from PEM-encoded certificate and key bytes.
func NewFromPEM(certPEM, keyPEM []byte, validity time.Duration) (*CA, error) {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("failed to decode CA certificate PEM")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA certificate: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("failed to decode CA key PEM")
	}

	key, err := parsePrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA key: %w", err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(cert)

	return &CA{
		cert:      cert,
		key:       key,
		validity:  validity,
		trustPool: pool,
	}, nil
}

// IssueCertificateFromCSR signs a Certificate Signing Request and returns the certificate.
// The private key stays on the agent - this method only signs the CSR.
func (ca *CA) IssueCertificateFromCSR(deviceID string, csrPEM []byte) (*Certificate, error) {
	// Parse the CSR
	csrBlock, _ := pem.Decode(csrPEM)
	if csrBlock == nil {
		return nil, fmt.Errorf("failed to decode CSR PEM")
	}

	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CSR: %w", err)
	}

	// Verify the CSR signature
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("invalid CSR signature: %w", err)
	}

	// Reject CSRs that request Subject Alternative Names. Agent
	// certificates are client certs identified by the deviceID in the
	// Subject CN — DNSNames, IPAddresses, EmailAddresses, and URIs have
	// no legitimate use here and would otherwise be copied into the
	// issued cert, letting a malicious agent request SANs for internal
	// hostnames (e.g. control-server.example.com) that downstream
	// verifiers might then trust.
	if len(csr.DNSNames) > 0 || len(csr.IPAddresses) > 0 || len(csr.EmailAddresses) > 0 || len(csr.URIs) > 0 {
		return nil, fmt.Errorf("CSR must not request subject alternative names")
	}

	// Generate serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial number: %w", err)
	}

	now := time.Now()
	notAfter := now.Add(ca.validity)

	// Stamp the SPIFFE URI SAN that marks this as an "agent" peer
	// class. The gateway's mTLS middleware requires this class on
	// its agent-facing listener, and the control server's internal
	// listener refuses agents — so even if an agent cert leaks, the
	// attacker cannot use it to reach the internal listener and
	// read other devices' LUKS keys or LPS passwords.
	peerURI, err := mtls.PeerClassURI(mtls.PeerClassAgent)
	if err != nil {
		return nil, fmt.Errorf("build peer-class URI: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   deviceID,
			Organization: []string{"power-manage"},
		},
		NotBefore:             now.Add(-1 * time.Minute), // Allow for clock skew
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		URIs:                  []*url.URL{peerURI},
	}

	// Add device ID to the Subject's SerialNumber field
	template.Subject.SerialNumber = deviceID

	// Sign the certificate using the public key from the CSR
	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.cert, csr.PublicKey, ca.key)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}

	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Calculate fingerprint (SHA256 of DER-encoded certificate)
	fingerprint := sha256.Sum256(certDER)

	return &Certificate{
		CertPEM:     certPEM,
		KeyPEM:      nil, // Private key stays on agent
		Fingerprint: hex.EncodeToString(fingerprint[:]),
		NotAfter:    notAfter,
	}, nil
}

// SetTrustBundle replaces the verification trust pool with all CA certificates
// parsed from the given PEM data. This supports CA rotation: the bundle should
// contain both the old and new CA certificates so that agent certs signed by
// either CA are accepted during the transition period.
func (ca *CA) SetTrustBundle(pemData []byte) error {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemData) {
		return fmt.Errorf("failed to parse any certificates from trust bundle")
	}
	ca.trustPool = pool
	return nil
}

// VerifyCertificate verifies a PEM-encoded certificate was signed by a trusted CA.
// Uses the trust pool (which may contain multiple CA certs for rotation).
// Returns the device ID (CN) if valid.
func (ca *CA) VerifyCertificate(certPEM []byte) (string, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", fmt.Errorf("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse certificate: %w", err)
	}

	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:     ca.trustPool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return "", fmt.Errorf("certificate verification failed: %w", err)
	}

	return cert.Subject.CommonName, nil
}

// TrustPool returns the CA trust pool used for certificate verification.
// This includes additional CAs added via SetTrustBundle for rotation support.
func (ca *CA) TrustPool() *x509.CertPool {
	return ca.trustPool
}

// Signer returns the CA's private key for action signing.
func (ca *CA) Signer() crypto.Signer {
	return ca.key
}

// CACertPEM returns the PEM-encoded CA certificate.
func (ca *CA) CACertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca.cert.Raw,
	})
}

// parsePrivateKey tries to parse a private key in various formats.
func parsePrivateKey(der []byte) (crypto.Signer, error) {
	// Try PKCS8 first
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		if signer, ok := key.(crypto.Signer); ok {
			return signer, nil
		}
	}

	// Try EC private key
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}

	// Try RSA private key (PKCS1)
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}

	return nil, fmt.Errorf("unsupported private key format")
}

// FingerprintFromPEM extracts the fingerprint from a PEM-encoded certificate.
func FingerprintFromPEM(certPEM []byte) (string, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", fmt.Errorf("failed to decode certificate PEM")
	}

	fingerprint := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(fingerprint[:]), nil
}

// DeviceIDFromPEM extracts the device ID from a PEM-encoded certificate.
func DeviceIDFromPEM(certPEM []byte) (string, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", fmt.Errorf("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse certificate: %w", err)
	}

	return cert.Subject.CommonName, nil
}
