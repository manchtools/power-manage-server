package ca_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/ca"
)

// generateTestCA creates a self-signed CA cert and key for testing.
func generateTestCA(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test CA",
			Organization: []string{"Test"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &caKey.PublicKey, caKey)
	require.NoError(t, err)

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(caKey)
	require.NoError(t, err)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM
}

// generateCSR creates a CSR PEM for a given device ID.
func generateCSR(t *testing.T, deviceID string) (csrPEM []byte, key *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: deviceID,
		},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, key)
	require.NoError(t, err)

	csrPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	return csrPEM, key
}

func TestNewFromPEM(t *testing.T) {
	certPEM, keyPEM := generateTestCA(t)

	c, err := ca.NewFromPEM(certPEM, keyPEM, 24*time.Hour)
	require.NoError(t, err)
	assert.NotNil(t, c)
}

func TestNewFromPEM_InvalidCert(t *testing.T) {
	_, keyPEM := generateTestCA(t)

	_, err := ca.NewFromPEM([]byte("not a cert"), keyPEM, 24*time.Hour)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "decode CA certificate PEM")
}

func TestNewFromPEM_InvalidKey(t *testing.T) {
	certPEM, _ := generateTestCA(t)

	_, err := ca.NewFromPEM(certPEM, []byte("not a key"), 24*time.Hour)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "decode CA key PEM")
}

func TestIssueCertificateFromCSR_Success(t *testing.T) {
	certPEM, keyPEM := generateTestCA(t)
	c, err := ca.NewFromPEM(certPEM, keyPEM, 24*time.Hour)
	require.NoError(t, err)

	csrPEM, _ := generateCSR(t, "device-001")

	cert, err := c.IssueCertificateFromCSR("device-001", csrPEM)
	require.NoError(t, err)
	assert.NotEmpty(t, cert.CertPEM)
	assert.Nil(t, cert.KeyPEM, "private key should stay on agent")
	assert.NotEmpty(t, cert.Fingerprint)
	assert.True(t, cert.NotAfter.After(time.Now()))
}

func TestIssueCertificateFromCSR_InvalidCSR(t *testing.T) {
	certPEM, keyPEM := generateTestCA(t)
	c, err := ca.NewFromPEM(certPEM, keyPEM, 24*time.Hour)
	require.NoError(t, err)

	_, err = c.IssueCertificateFromCSR("device-001", []byte("not a csr"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "decode CSR PEM")
}

func TestVerifyCertificate_Success(t *testing.T) {
	certPEM, keyPEM := generateTestCA(t)
	c, err := ca.NewFromPEM(certPEM, keyPEM, 24*time.Hour)
	require.NoError(t, err)

	csrPEM, _ := generateCSR(t, "device-001")
	issued, err := c.IssueCertificateFromCSR("device-001", csrPEM)
	require.NoError(t, err)

	deviceID, err := c.VerifyCertificate(issued.CertPEM)
	require.NoError(t, err)
	assert.Equal(t, "device-001", deviceID)
}

func TestVerifyCertificate_WrongCA(t *testing.T) {
	certPEM1, keyPEM1 := generateTestCA(t)
	c1, err := ca.NewFromPEM(certPEM1, keyPEM1, 24*time.Hour)
	require.NoError(t, err)

	certPEM2, keyPEM2 := generateTestCA(t)
	c2, err := ca.NewFromPEM(certPEM2, keyPEM2, 24*time.Hour)
	require.NoError(t, err)

	// Issue cert with CA1
	csrPEM, _ := generateCSR(t, "device-001")
	issued, err := c1.IssueCertificateFromCSR("device-001", csrPEM)
	require.NoError(t, err)

	// Verify with CA2 should fail
	_, err = c2.VerifyCertificate(issued.CertPEM)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "verification failed")
}

func TestVerifyCertificate_InvalidPEM(t *testing.T) {
	certPEM, keyPEM := generateTestCA(t)
	c, err := ca.NewFromPEM(certPEM, keyPEM, 24*time.Hour)
	require.NoError(t, err)

	_, err = c.VerifyCertificate([]byte("not a certificate"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "decode certificate PEM")
}

func TestCACertPEM(t *testing.T) {
	certPEM, keyPEM := generateTestCA(t)
	c, err := ca.NewFromPEM(certPEM, keyPEM, 24*time.Hour)
	require.NoError(t, err)

	caCert := c.CACertPEM()
	assert.NotEmpty(t, caCert)

	block, _ := pem.Decode(caCert)
	require.NotNil(t, block)
	assert.Equal(t, "CERTIFICATE", block.Type)
}

func TestFingerprintFromPEM(t *testing.T) {
	certPEM, keyPEM := generateTestCA(t)
	c, err := ca.NewFromPEM(certPEM, keyPEM, 24*time.Hour)
	require.NoError(t, err)

	csrPEM, _ := generateCSR(t, "device-001")
	issued, err := c.IssueCertificateFromCSR("device-001", csrPEM)
	require.NoError(t, err)

	fp, err := ca.FingerprintFromPEM(issued.CertPEM)
	require.NoError(t, err)
	assert.Equal(t, issued.Fingerprint, fp)
}

func TestFingerprintFromPEM_InvalidPEM(t *testing.T) {
	_, err := ca.FingerprintFromPEM([]byte("not a certificate"))
	assert.Error(t, err)
}

func TestDeviceIDFromPEM(t *testing.T) {
	certPEM, keyPEM := generateTestCA(t)
	c, err := ca.NewFromPEM(certPEM, keyPEM, 24*time.Hour)
	require.NoError(t, err)

	csrPEM, _ := generateCSR(t, "device-002")
	issued, err := c.IssueCertificateFromCSR("device-002", csrPEM)
	require.NoError(t, err)

	deviceID, err := ca.DeviceIDFromPEM(issued.CertPEM)
	require.NoError(t, err)
	assert.Equal(t, "device-002", deviceID)
}

func TestDeviceIDFromPEM_InvalidPEM(t *testing.T) {
	_, err := ca.DeviceIDFromPEM([]byte("not a certificate"))
	assert.Error(t, err)
}

func TestSetTrustBundle(t *testing.T) {
	certPEM1, keyPEM1 := generateTestCA(t)
	c1, err := ca.NewFromPEM(certPEM1, keyPEM1, 24*time.Hour)
	require.NoError(t, err)

	certPEM2, keyPEM2 := generateTestCA(t)
	c2, err := ca.NewFromPEM(certPEM2, keyPEM2, 24*time.Hour)
	require.NoError(t, err)

	// Issue cert with CA2
	csrPEM, _ := generateCSR(t, "device-001")
	issued, err := c2.IssueCertificateFromCSR("device-001", csrPEM)
	require.NoError(t, err)

	// CA1 cannot verify CA2-issued cert
	_, err = c1.VerifyCertificate(issued.CertPEM)
	assert.Error(t, err)

	// Add CA2 cert to CA1's trust bundle
	bundle := append(certPEM1, certPEM2...)
	err = c1.SetTrustBundle(bundle)
	require.NoError(t, err)

	// Now CA1 can verify CA2-issued cert
	deviceID, err := c1.VerifyCertificate(issued.CertPEM)
	require.NoError(t, err)
	assert.Equal(t, "device-001", deviceID)
}

func TestSetTrustBundle_InvalidPEM(t *testing.T) {
	certPEM, keyPEM := generateTestCA(t)
	c, err := ca.NewFromPEM(certPEM, keyPEM, 24*time.Hour)
	require.NoError(t, err)

	err = c.SetTrustBundle([]byte("not a certificate"))
	assert.Error(t, err)
}

func TestSigner(t *testing.T) {
	certPEM, keyPEM := generateTestCA(t)
	c, err := ca.NewFromPEM(certPEM, keyPEM, 24*time.Hour)
	require.NoError(t, err)

	signer := c.Signer()
	assert.NotNil(t, signer)
	assert.NotNil(t, signer.Public())
}

func TestTrustPool(t *testing.T) {
	certPEM, keyPEM := generateTestCA(t)
	c, err := ca.NewFromPEM(certPEM, keyPEM, 24*time.Hour)
	require.NoError(t, err)

	pool := c.TrustPool()
	assert.NotNil(t, pool)
}
