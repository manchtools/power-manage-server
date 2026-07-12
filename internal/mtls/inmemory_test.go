package mtls_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/mtls"
)

// selfSigned builds a self-signed leaf keypair (cert PEM + key PEM) for CN.
func selfSigned(t *testing.T, cn string) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

func TestNewServerTLSConfigFromPEM(t *testing.T) {
	certPEM, keyPEM := selfSigned(t, "gateway")
	caPEM, _ := selfSigned(t, "ca")

	cfg, err := mtls.NewServerTLSConfigFromPEM(certPEM, keyPEM, caPEM)
	require.NoError(t, err)
	require.Len(t, cfg.Certificates, 1)
	assert.Equal(t, tls.RequireAndVerifyClientCert, cfg.ClientAuth)
	assert.Equal(t, uint16(tls.VersionTLS13), cfg.MinVersion)
	assert.NotNil(t, cfg.ClientCAs)

	// A bad CA PEM is rejected.
	_, err = mtls.NewServerTLSConfigFromPEM(certPEM, keyPEM, []byte("not a ca"))
	assert.Error(t, err)
	// A mismatched cert/key is rejected.
	_, otherKey := selfSigned(t, "other")
	_, err = mtls.NewServerTLSConfigFromPEM(certPEM, otherKey, caPEM)
	assert.Error(t, err)
}

func TestCertRotator_Swap(t *testing.T) {
	certAPEM, keyAPEM := selfSigned(t, "a")
	certA, err := tls.X509KeyPair(certAPEM, keyAPEM)
	require.NoError(t, err)
	certBPEM, keyBPEM := selfSigned(t, "b")
	certB, err := tls.X509KeyPair(certBPEM, keyBPEM)
	require.NoError(t, err)

	r := mtls.NewCertRotator(certA)
	got, err := r.GetCertificate(&tls.ClientHelloInfo{})
	require.NoError(t, err)
	require.Equal(t, certA.Certificate, got.Certificate)

	// After a swap, both the server and client callbacks return the new cert.
	r.Set(certB)
	got, err = r.GetCertificate(&tls.ClientHelloInfo{})
	require.NoError(t, err)
	assert.Equal(t, certB.Certificate, got.Certificate)
	gotClient, err := r.GetClientCertificate(&tls.CertificateRequestInfo{})
	require.NoError(t, err)
	assert.Equal(t, certB.Certificate, gotClient.Certificate)

	// The rotator can seed both a server and a client TLS config wired to the
	// callbacks.
	caPEM, _ := selfSigned(t, "ca")
	srvCfg, err := r.ServerTLSConfig(caPEM)
	require.NoError(t, err)
	assert.NotNil(t, srvCfg.GetCertificate)
	cliCfg, err := r.ClientTLSConfig(caPEM)
	require.NoError(t, err)
	assert.NotNil(t, cliCfg.GetClientCertificate)
}
