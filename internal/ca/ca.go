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
	"os"
	"time"
)

// CA is a certificate authority that issues device certificates.
type CA struct {
	cert     *x509.Certificate
	key      crypto.Signer
	validity time.Duration
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

	return &CA{
		cert:     cert,
		key:      key,
		validity: validity,
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

	// Generate serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial number: %w", err)
	}

	now := time.Now()
	notAfter := now.Add(ca.validity)

	// Use hostname from CSR's CommonName
	hostname := csr.Subject.CommonName
	if hostname == "" {
		hostname = "unknown"
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   hostname,
			Organization: []string{"power-manage"},
		},
		NotBefore:             now.Add(-1 * time.Minute), // Allow for clock skew
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              csr.DNSNames,
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

	return cert.Subject.SerialNumber, nil
}
