package ca_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/ca"
)

func pkcs8PEM(t *testing.T, key any) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func TestNewFromPEM_RequiresMatchingEd25519Key(t *testing.T) {
	certPEM, ed25519KeyPEM := generateTestCA(t)
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	_, otherEd25519Key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	t.Run("matching Ed25519 accepted", func(t *testing.T) {
		_, err := ca.NewFromPEM(certPEM, ed25519KeyPEM, time.Hour)
		require.NoError(t, err)
	})
	t.Run("ECDSA rejected", func(t *testing.T) {
		_, err := ca.NewFromPEM(certPEM, pkcs8PEM(t, ecdsaKey), time.Hour)
		require.ErrorContains(t, err, "Ed25519 is required")
	})
	t.Run("RSA rejected", func(t *testing.T) {
		_, err := ca.NewFromPEM(certPEM, pkcs8PEM(t, rsaKey), time.Hour)
		require.ErrorContains(t, err, "Ed25519 is required")
	})
	t.Run("mismatched Ed25519 rejected", func(t *testing.T) {
		_, err := ca.NewFromPEM(certPEM, pkcs8PEM(t, otherEd25519Key), time.Hour)
		require.ErrorContains(t, err, "do not match")
	})
}

func TestIssueCertificateFromCSR_RejectsNonEd25519Identity(t *testing.T) {
	certPEM, keyPEM := generateTestCA(t)
	c, err := ca.NewFromPEM(certPEM, keyPEM, time.Hour)
	require.NoError(t, err)
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "device-1"},
	}, ecdsaKey)
	require.NoError(t, err)
	_, err = c.IssueCertificateFromCSR("device-1", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
	require.ErrorContains(t, err, "Ed25519 is required")
}

// TestNew_WarnsOnGroupOrWorldReadableKeyFile pins WS10 #11: New warns
// loudly (but does not fail) when the CA private key file is
// group/world-accessible. A 0600 key is silent; a 0644 key warns with
// the path.
func TestNew_WarnsOnGroupOrWorldReadableKeyFile(t *testing.T) {
	certPEM, keyPEM := generateTestCA(t)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")
	require.NoError(t, os.WriteFile(certPath, certPEM, 0o600))
	require.NoError(t, os.WriteFile(keyPath, keyPEM, 0o600))

	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	t.Run("0600 owner-only is silent", func(t *testing.T) {
		buf.Reset()
		require.NoError(t, os.Chmod(keyPath, 0o600))
		_, err := ca.New(certPath, keyPath, time.Hour)
		require.NoError(t, err)
		require.NotContains(t, buf.String(), "group/world")
	})
	t.Run("0644 world-readable warns with the path", func(t *testing.T) {
		buf.Reset()
		require.NoError(t, os.Chmod(keyPath, 0o644))
		_, err := ca.New(certPath, keyPath, time.Hour)
		require.NoError(t, err) // warn-only, not a hard failure
		require.Contains(t, buf.String(), "group/world")
		require.Contains(t, buf.String(), keyPath)
	})
}
