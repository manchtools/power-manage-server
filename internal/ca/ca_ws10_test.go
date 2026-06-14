package ca_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
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

// TestNewFromPEM_RejectsSignerIncompatibleCAKey pins WS10 #7: the CA key
// signs both issued certs AND dispatched actions (the action signer
// supports only ECDSA/RSA). A signer-incompatible key (Ed25519 — valid
// PKCS8, implements crypto.Signer, accepted by parsePrivateKey) must be
// rejected at boot rather than load and silently break action dispatch.
func TestNewFromPEM_RejectsSignerIncompatibleCAKey(t *testing.T) {
	certPEM, ecdsaKeyPEM := generateTestCA(t)

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	_, ed25519Key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	t.Run("ECDSA accepted", func(t *testing.T) {
		_, err := ca.NewFromPEM(certPEM, ecdsaKeyPEM, time.Hour)
		require.NoError(t, err)
	})
	t.Run("RSA accepted", func(t *testing.T) {
		_, err := ca.NewFromPEM(certPEM, pkcs8PEM(t, rsaKey), time.Hour)
		require.NoError(t, err)
	})
	t.Run("Ed25519 rejected", func(t *testing.T) {
		_, err := ca.NewFromPEM(certPEM, pkcs8PEM(t, ed25519Key), time.Hour)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported CA signing key type")
	})
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
