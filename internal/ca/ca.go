// Package ca provides a certificate authority for issuing device certificates.
package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log/slog"
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
	trustPool *x509.CertPool   // trust bundle for verification (supports CA rotation)
	now       func() time.Time // clock seam; defaults to time.Now, overridden in tests
}

// Option configures a CA.
type Option func(*CA)

// WithClock overrides the time source (tests). The default is time.Now.
func WithClock(now func() time.Time) Option { return func(c *CA) { c.now = now } }

// Certificate holds a PEM-encoded certificate and private key.
type Certificate struct {
	CertPEM     []byte
	KeyPEM      []byte
	Fingerprint string
	NotAfter    time.Time
}

// New creates a new CA from PEM-encoded certificate and key files.
func New(certPath, keyPath string, validity time.Duration, opts ...Option) (*CA, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read CA certificate: %w", err)
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read CA key: %w", err)
	}

	// WS10 #11: the CA private key is the root of all trust — warn loudly
	// (but do not block startup) if it is group/world-accessible. A hard
	// failure here would break an existing deployment with a looser key
	// mode; the operator must tighten it to owner-only (0600).
	if info, statErr := os.Stat(keyPath); statErr == nil && info.Mode().Perm()&0o077 != 0 {
		slog.Warn("CA private key file is group/world-accessible — restrict it to owner-only (chmod 0600)",
			"path", keyPath, "mode", fmt.Sprintf("%#o", info.Mode().Perm()))
	}

	return NewFromPEM(certPEM, keyPEM, validity, opts...)
}

// NewFromPEM creates a new CA from PEM-encoded certificate and key bytes.
func NewFromPEM(certPEM, keyPEM []byte, validity time.Duration, opts ...Option) (*CA, error) {
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

	// WS10 #7: the CA key signs BOTH issued certificates and dispatched
	// actions (verify.ActionSigner), which supports only ECDSA and RSA.
	// parsePrivateKey accepts any crypto.Signer (e.g. an Ed25519 PKCS8
	// key) — reject a signer-incompatible key at boot rather than load it
	// and silently break action dispatch later.
	switch key.(type) {
	case *ecdsa.PrivateKey, *rsa.PrivateKey:
		// supported
	default:
		return nil, fmt.Errorf("unsupported CA signing key type %T (the action signer requires ECDSA or RSA)", key)
	}

	pool := x509.NewCertPool()
	pool.AddCert(cert)

	c := &CA{
		cert:      cert,
		key:       key,
		validity:  validity,
		trustPool: pool,
		now:       time.Now,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c, nil
}

// gatewayCertValidity is the fixed short-lived TTL for gateway certificates
// (spec 31 AC7): 45 days, distinct from the agent-cert ca.validity. Short-lived
// so an abandoned or revoked gateway cert self-expires within the window even if
// the CRL is unavailable.
const gatewayCertValidity = 45 * 24 * time.Hour

// IssueCertificateFromCSR signs an agent Certificate Signing Request and returns
// the certificate. The private key stays on the agent - this method only signs
// the CSR. Agent certs carry the agent peer class and the CA's default validity.
func (ca *CA) IssueCertificateFromCSR(deviceID string, csrPEM []byte) (*Certificate, error) {
	return ca.issueFromCSR(deviceID, csrPEM, mtls.PeerClassAgent, ca.validity, nil)
}

// IssueGatewayCertificateFromCSR signs a gateway CSR (spec 31). The issued cert
// carries CN = SerialNumber = gatewayID, the gateway peer-class SAN, the fixed
// 45-day gateway validity, and — when hostname is non-empty — a server-chosen
// DNS SAN for that hostname. The DNS SAN is load-bearing: an agent connects to
// the gateway by hostname and verifies its server cert with STANDARD TLS
// (ServerName match against DNS SANs), so a gateway cert without a DNS SAN
// matching its public hostname cannot be verified. hostname is NOT a CSR-supplied
// SAN: on enrollment it is the enroller's self-reported EnrollGateway request
// hostname (proto format-validated only — there is no operator hostname
// allow-list today, so a CONTROL_GATEWAY_ENROLL_TOKEN holder can request any DNS
// SAN; the gateway identity/CN is still a server-minted ULID, so this is not
// identity forgery — audit L1); on renewal it is the current cert's
// previously-server-stamped DNS SAN. Callers reach this from GatewayAuthService
// enrollment and InternalService renewal.
func (ca *CA) IssueGatewayCertificateFromCSR(gatewayID string, csrPEM []byte, hostname string) (*Certificate, error) {
	var dnsNames []string
	if hostname != "" {
		dnsNames = []string{hostname}
	}
	return ca.issueFromCSR(gatewayID, csrPEM, mtls.PeerClassGateway, gatewayCertValidity, dnsNames)
}

// issueFromCSR is the shared issuance body. deviceID becomes the cert CN and
// Subject.SerialNumber; class selects the peer-class URI SAN stamped on the
// cert; validity sets NotAfter; dnsNames are server-chosen DNS SANs (gateway
// hostname). The CA authoritatively stamps the identity, class, and any DNS
// SANs — caller-supplied SANs in the CSR are rejected below — so an enrolling
// peer can never mint a different identity, peer class, or hostname than the
// server assigns.
func (ca *CA) issueFromCSR(deviceID string, csrPEM []byte, class mtls.PeerClass, validity time.Duration, dnsNames []string) (*Certificate, error) {
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

	now := ca.now()
	notAfter := now.Add(validity)

	// Stamp the SPIFFE URI SAN that marks this cert's peer class. The
	// gateway's mTLS middleware requires the agent class on its agent-facing
	// listener, and the control server's internal listener requires the
	// gateway class — so even if an agent cert leaks, the attacker cannot use
	// it to reach the internal listener and read other devices' LUKS keys or
	// LPS passwords. The class is server-chosen here, never CSR-supplied.
	peerURI, err := mtls.PeerClassURI(class)
	if err != nil {
		return nil, fmt.Errorf("build peer-class URI: %w", err)
	}

	// Agent certs are TLS clients only. A gateway cert is BOTH a client (to
	// control's internal listener) AND the TLS server cert on its agent-facing
	// mTLS listener, so it also needs ServerAuth — an agent verifies the
	// gateway's server cert with the ServerAuth EKU, which a client-only cert
	// would fail (spec 31).
	extKeyUsage := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	if class == mtls.PeerClassGateway {
		extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageServerAuth)
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
		ExtKeyUsage:           extKeyUsage,
		BasicConstraintsValid: true,
		URIs:                  []*url.URL{peerURI},
		// Server-chosen DNS SANs (gateway hostname). Empty for agent certs.
		DNSNames: dnsNames,
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

// NotAfterFromPEM returns the expiry of a PEM-encoded certificate. Used to set
// the CRL entry's TTL to the revoked cert's own lifetime — a revoked cert never
// needs to outlive its expiry on the list (mTLS rejects an expired cert anyway).
func NotAfterFromPEM(certPEM []byte) (time.Time, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return time.Time{}, fmt.Errorf("failed to decode certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse certificate: %w", err)
	}
	return cert.NotAfter, nil
}

// FingerprintFromCert computes the fingerprint of an already-parsed
// certificate. It is byte-for-byte identical to FingerprintFromPEM /
// IssueCertificateFromCSR (hex of SHA-256 over the DER), so a fingerprint the
// control server stored or revoked matches one the gateway derives from the
// cert presented on an mTLS connection. cert.Raw is the DER encoding.
func FingerprintFromCert(cert *x509.Certificate) string {
	// Defensive: callers reach this from the gateway mTLS path where the leaf is
	// already verified non-nil, but never panic on a hot request path. An empty
	// fingerprint matches no revoked entry — a nil cert is already rejected by
	// the peer-class / TLS checks upstream, so this fails safe, not open.
	if cert == nil {
		return ""
	}
	fingerprint := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(fingerprint[:])
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

// PeerClassFromPEM extracts the SPIFFE peer class from a PEM-encoded
// certificate's URI SAN. Mirrors DeviceIDFromPEM/NotAfterFromPEM so the API
// handlers can assert a presented cert's class without re-implementing the
// decode. Delegates the URI-SAN parsing to mtls.PeerClassFromCert (single
// source of truth for the class layout).
func PeerClassFromPEM(certPEM []byte) (mtls.PeerClass, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", fmt.Errorf("failed to decode certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse certificate: %w", err)
	}
	return mtls.PeerClassFromCert(cert)
}

// AssertCSRMatchesCertKey verifies that the CSR's public key equals the
// certificate's public key. On certificate renewal this is the
// proof-of-possession: the renewer must hold the private key bound to the cert
// it presented, which agents do because they reuse their keypair
// (GenerateCSRFromKey). Without it, certificates are public material — returned
// at registration and stored in the event log — so anyone who reads a device's
// cert PEM could submit a CSR for a key they control and mint an impersonation
// cert bound to that device id (#361).
func AssertCSRMatchesCertKey(certPEM, csrPEM []byte) error {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return fmt.Errorf("failed to decode certificate PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parse certificate: %w", err)
	}

	csrBlock, _ := pem.Decode(csrPEM)
	if csrBlock == nil {
		return fmt.Errorf("failed to decode CSR PEM")
	}
	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parse CSR: %w", err)
	}

	// crypto.PublicKey for ecdsa/rsa/ed25519 implements Equal; compare via it
	// rather than re-encoding so a curve/parameter mismatch can't slip through.
	type equalKey interface {
		Equal(crypto.PublicKey) bool
	}
	certKey, ok := cert.PublicKey.(equalKey)
	if !ok {
		return fmt.Errorf("unsupported certificate public key type %T", cert.PublicKey)
	}
	if !certKey.Equal(csr.PublicKey) {
		return fmt.Errorf("CSR public key does not match the current certificate")
	}
	return nil
}
