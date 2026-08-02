package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadConfigUsesOneFileAndSecretFiles(t *testing.T) {
	for _, environment := range []string{
		"POWER_MANAGE_DATABASE_URL", "POWER_MANAGE_DATABASE_URL_FILE",
		"POWER_MANAGE_ENCRYPTION_KEY", "POWER_MANAGE_ENCRYPTION_KEY_FILE",
		"POWER_MANAGE_SESSION_SIGNING_KEY_FILE", "POWER_MANAGE_SEALING_KEY_FILE",
		"POWER_MANAGE_CA_KEY_FILE", "POWER_MANAGE_AGENT_TLS_KEY_FILE", "POWER_MANAGE_PUBLIC_TLS_KEY_FILE",
	} {
		t.Setenv(environment, "")
	}
	directory := t.TempDir()
	secret := func(name, value string) string {
		path := filepath.Join(directory, name)
		require.NoError(t, os.WriteFile(path, []byte(value), 0o600))
		return path
	}
	_, sessionPrivate, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	encodedSession, err := x509.MarshalPKCS8PrivateKey(sessionPrivate)
	require.NoError(t, err)
	sessionPath := secret("session.pem", string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encodedSession})))
	sealingPath := secret("sealing.key", strings.Repeat("01", 32))
	databasePath := secret("database.url", "postgres://control:secret@db/control?sslmode=verify-full")
	encryptionPath := secret("encryption.key", strings.Repeat("02", 32))
	artifactPath := filepath.Join(directory, "artifacts")
	backupPath := filepath.Join(directory, "backups")
	require.NoError(t, os.Mkdir(artifactPath, 0o700))
	require.NoError(t, os.Mkdir(backupPath, 0o700))
	configPath := filepath.Join(directory, "control.json")
	document := `{
  "public_base_url": "https://manage.example",
  "agent_url": "https://agents.example",
  "terminal_url": "wss://manage.example/terminal",
  "cors_origins": ["https://manage.example"],
  "agent_proxy_sources": ["172.30.0.2"],
	"artifact_path": ` + quote(artifactPath) + `,
	"backup_path": ` + quote(backupPath) + `,
  "ca_cert_file": "/certs/ca.crt",
  "ca_key_file": "/certs/ca.key",
  "agent_tls_cert_file": "/certs/control.crt",
  "agent_tls_key_file": "/certs/control.key",
  "database_url_file": ` + quote(databasePath) + `,
  "encryption_key_file": ` + quote(encryptionPath) + `,
  "session_signing_key_file": ` + quote(sessionPath) + `,
  "sealing_key_file": ` + quote(sealingPath) + `
}`
	require.NoError(t, os.WriteFile(configPath, []byte(document), 0o600))

	cfg, err := loadConfig([]string{"-config", configPath})
	require.NoError(t, err)
	assert.Equal(t, ":8081", cfg.PublicListen)
	assert.Equal(t, ":8082", cfg.AgentListen)
	assert.Equal(t, []string{"172.30.0.2"}, cfg.AgentProxySources)
	assert.Equal(t, "manage.example", cfg.TerminalOrigins[0])
	assert.Equal(t, artifactPath, cfg.ArtifactPath)
	assert.Equal(t, backupPath, cfg.BackupPath)
	assert.Equal(t, 90*24*time.Hour, cfg.AuditRetention)
	assert.Equal(t, sessionPrivate, cfg.SessionSigningKey)
	assert.Equal(t, bytes.Repeat([]byte{1}, 32), cfg.SealingKey.Bytes())
}

func TestValidateConfigRequiresWritableDataDirectories(t *testing.T) {
	file := filepath.Join(t.TempDir(), "not-a-directory")
	require.NoError(t, os.WriteFile(file, []byte("x"), 0o600))

	err := validateWritableDirectory("artifact_path", file)
	assert.ErrorContains(t, err, "must be a directory")
	assert.ErrorContains(t, validateWritableDirectory("backup_path", ""), "is required")
}

func TestConfigAndSecretReadersFailClosed(t *testing.T) {
	directory := t.TempDir()
	unknown := filepath.Join(directory, "unknown.json")
	require.NoError(t, os.WriteFile(unknown, []byte(`{"unknown":true}`), 0o600))
	var document configDocument
	assert.Error(t, decodeConfigFile(unknown, &document))

	loose := filepath.Join(directory, "loose.key")
	require.NoError(t, os.WriteFile(loose, []byte("secret"), 0o644))
	_, err := readSecretFile(loose)
	assert.Error(t, err)
}

func quote(value string) string {
	return strconv.Quote(value)
}
