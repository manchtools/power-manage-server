package main

// Smoke coverage for the HTTP-server boot helpers (audit F043 / #157,
// slice 2). The builders own enough TLS plumbing that a regression in
// the disabled→TLS branch (or the mTLS verification mode) would be
// invisible until prod boot — tests here lock the resulting *http.Server
// fields in place against a pair of self-signed certs generated for
// the test only.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/ca"
)

// writeSelfSignedCert mints an ECDSA P-256 self-signed cert + key in
// PEM form, writes them to tmpdir, and returns the on-disk paths.
// ECDSA keeps the test cheap (no RSA key gen) and the resulting cert
// is enough for tls.LoadX509KeyPair to succeed.
func writeSelfSignedCert(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(1 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	require.NoError(t, err)
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")

	certPEM, err := os.Create(certPath)
	require.NoError(t, err)
	require.NoError(t, pem.Encode(certPEM, &pem.Block{Type: "CERTIFICATE", Bytes: der}))
	require.NoError(t, certPEM.Close())

	keyDER, err := x509.MarshalECPrivateKey(priv)
	require.NoError(t, err)
	keyPEM, err := os.Create(keyPath)
	require.NoError(t, err)
	require.NoError(t, pem.Encode(keyPEM, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	require.NoError(t, keyPEM.Close())

	return certPath, keyPath
}

// =============================================================================
// buildPublicServer
// =============================================================================

func TestBuildPublicServer_PlainHTTPWhenTLSDisabled(t *testing.T) {
	srv, err := buildPublicServer(&Config{
		ListenAddr: ":0",
		TLSEnabled: false,
	}, http.NewServeMux())
	require.NoError(t, err)
	require.NotNil(t, srv)

	assert.Equal(t, ":0", srv.Addr)
	assert.Nil(t, srv.TLSConfig, "TLSConfig must be nil when TLS is disabled — h1 plain serve")
	assert.Equal(t, 120*time.Second, srv.IdleTimeout)
	assert.Equal(t, 10*time.Second, srv.ReadHeaderTimeout)
}

func TestBuildPublicServer_TLSConfigPopulatedWhenEnabled(t *testing.T) {
	dir := t.TempDir()
	cert, key := writeSelfSignedCert(t, dir)
	srv, err := buildPublicServer(&Config{
		ListenAddr: ":0",
		TLSEnabled: true,
		TLSCert:    cert,
		TLSKey:     key,
	}, http.NewServeMux())
	require.NoError(t, err)
	require.NotNil(t, srv.TLSConfig)
	assert.Equal(t, uint16(tls.VersionTLS13), srv.TLSConfig.MinVersion,
		"public TLS must pin TLS 1.3 — older TLS is rejected at the listener for compliance")
	assert.Len(t, srv.TLSConfig.Certificates, 1)
}

func TestBuildPublicServer_BadCertReturnsErrorNotPanic(t *testing.T) {
	// A misconfigured cert path (operator typo) MUST surface as an
	// error so main() can log + exit cleanly. The prior shape called
	// log.Fatal — equally safe but harder to test; the helper now
	// returns the error so a unit test can exercise this branch.
	_, err := buildPublicServer(&Config{
		ListenAddr: ":0",
		TLSEnabled: true,
		TLSCert:    "/nonexistent/cert.pem",
		TLSKey:     "/nonexistent/key.pem",
	}, http.NewServeMux())
	require.Error(t, err)
	assert.ErrorContains(t, err, "load public TLS key pair",
		"error must be wrapped with the source phase so the operator-facing log line points at the right config knob")
}

// =============================================================================
// buildInternalServer
// =============================================================================

func TestBuildInternalServer_RequiresClientCertVerification(t *testing.T) {
	// The mTLS contract is the entire reason this listener exists —
	// the gateway proves identity via its CA-signed client cert. If
	// ClientAuth ever drifts from RequireAndVerifyClientCert, every
	// credential-bearing proxy call (LUKS keys, LPS passwords) becomes
	// reachable from any TLS client. Lock it.
	dir := t.TempDir()
	cert, key := writeSelfSignedCert(t, dir)
	authority, err := ca.New(cert, key, 1*time.Hour)
	require.NoError(t, err)

	srv, err := buildInternalServer(&Config{
		InternalListenAddr: ":0",
		InternalTLSCert:    cert,
		InternalTLSKey:     key,
	}, authority, http.NewServeMux())
	require.NoError(t, err)
	require.NotNil(t, srv.TLSConfig)
	assert.Equal(t, tls.RequireAndVerifyClientCert, srv.TLSConfig.ClientAuth,
		"internal mTLS listener MUST require + verify client certs — the entire trust model depends on this")
	assert.NotNil(t, srv.TLSConfig.ClientCAs, "ClientCAs must be wired from the CA TrustPool")
	assert.Equal(t, uint16(tls.VersionTLS13), srv.TLSConfig.MinVersion)
	assert.Len(t, srv.TLSConfig.Certificates, 1)
}

func TestBuildInternalServer_BadCertReturnsErrorNotPanic(t *testing.T) {
	dir := t.TempDir()
	cert, key := writeSelfSignedCert(t, dir)
	authority, err := ca.New(cert, key, 1*time.Hour)
	require.NoError(t, err)

	_, err = buildInternalServer(&Config{
		InternalListenAddr: ":0",
		InternalTLSCert:    "/nonexistent/cert.pem",
		InternalTLSKey:     "/nonexistent/key.pem",
	}, authority, http.NewServeMux())
	require.Error(t, err)
	assert.ErrorContains(t, err, "load internal TLS key pair")
}
