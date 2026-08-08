package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// environmentFixture is a configuration that loads successfully, so each test
// can express exactly one deviation from it.
type environmentFixture struct {
	values     map[string]string
	sessionKey ed25519.PrivateKey
}

// newEnvironmentFixture writes the key material a full configuration needs and
// returns the variables that make loadConfig succeed.
func newEnvironmentFixture(t *testing.T) environmentFixture {
	t.Helper()
	directory := t.TempDir()
	write := func(name, content string) string {
		path := filepath.Join(directory, name)
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
		return path
	}
	_, sessionKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	encodedSession, err := x509.MarshalPKCS8PrivateKey(sessionKey)
	require.NoError(t, err)
	sessionPath := write("session.pem",
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encodedSession})))
	artifactPath := filepath.Join(directory, "artifacts")
	backupPath := filepath.Join(directory, "backups")
	require.NoError(t, os.Mkdir(artifactPath, 0o700))
	require.NoError(t, os.Mkdir(backupPath, 0o700))
	// A configuration that loads successfully now needs the audit archive on
	// its own mount, which a test cannot create without root — so the fixture
	// models one. Cases that are about the separation itself put the real
	// probe back with useRealFilesystemProbe.
	modelSeparateFilesystems(t, backupPath)

	return environmentFixture{
		sessionKey: sessionKey,
		values: map[string]string{
			"POWER_MANAGE_PUBLIC_BASE_URL":          "https://manage.example",
			"POWER_MANAGE_AGENT_URL":                "https://agents.example",
			"POWER_MANAGE_TERMINAL_URL":             "wss://manage.example/terminal",
			"POWER_MANAGE_WEBHOOK_URL":              "https://hooks.example.test/power-manage?token=secret",
			"POWER_MANAGE_CORS_ORIGINS":             "https://manage.example",
			"POWER_MANAGE_AGENT_PROXY_SOURCES":      "172.30.0.2",
			"POWER_MANAGE_ARTIFACT_PATH":            artifactPath,
			"POWER_MANAGE_BACKUP_PATH":              backupPath,
			"POWER_MANAGE_CA_CERT_FILE":             "/certs/ca.crt",
			"POWER_MANAGE_CA_KEY_FILE":              "/certs/ca.key",
			"POWER_MANAGE_AGENT_TLS_CERT_FILE":      "/certs/control.crt",
			"POWER_MANAGE_AGENT_TLS_KEY_FILE":       "/certs/control.key",
			"POWER_MANAGE_DATABASE_PATH":            filepath.Join(directory, "control.db"),
			"POWER_MANAGE_ENCRYPTION_KEY_FILE":      write("encryption.key", strings.Repeat("02", 32)),
			"POWER_MANAGE_SESSION_SIGNING_KEY_FILE": sessionPath,
			"POWER_MANAGE_SEALING_KEY_FILE":         write("sealing.key", strings.Repeat("01", 32)),
		},
	}
}

// setEnvironment installs exactly the given variables for one test. The loader
// reads the environment through configEnviron, so POWER_MANAGE_ variables that
// happen to exist in the developer's shell cannot leak into a fixture;
// t.Setenv keeps the real process environment in agreement with the seam.
func setEnvironment(t *testing.T, values map[string]string) {
	t.Helper()
	entries := make([]string, 0, len(values))
	for name, value := range values {
		t.Setenv(name, value)
		entries = append(entries, name+"="+value)
	}
	previous := configEnviron
	configEnviron = func() []string { return entries }
	t.Cleanup(func() { configEnviron = previous })
}

// modelSeparateFilesystems makes archivePath report a filesystem of its own
// while every other path keeps its real identifier, so a stat failure still
// surfaces instead of being masked by the model.
func modelSeparateFilesystems(t *testing.T, archivePath string) {
	t.Helper()
	real := filesystemIDOf
	filesystemIDOf = func(path string) (uint64, error) {
		id, err := real(path)
		if err != nil || path != archivePath {
			return id, err
		}
		return id + 1, nil
	}
	t.Cleanup(func() { filesystemIDOf = real })
}

// useRealFilesystemProbe undoes the fixture's model for cases that must be
// judged against the kernel's answer.
func useRealFilesystemProbe(t *testing.T) {
	t.Helper()
	modelled := filesystemIDOf
	filesystemIDOf = filesystemDeviceID
	t.Cleanup(func() { filesystemIDOf = modelled })
}

func TestLoadConfigResolvesEveryOptionFromTheEnvironment(t *testing.T) {
	fixture := newEnvironmentFixture(t)
	fixture.values["POWER_MANAGE_CORS_ORIGINS"] = "https://manage.example, https://admin.example"
	fixture.values["POWER_MANAGE_TRUSTED_PROXIES"] = "10.0.0.1 , 10.0.0.2"
	fixture.values["POWER_MANAGE_CORS_ALLOW_ALL"] = "true"
	fixture.values["POWER_MANAGE_HEARTBEAT_INTERVAL"] = "45s"
	fixture.values["POWER_MANAGE_LOG_LEVEL"] = "debug"
	fixture.values["POWER_MANAGE_CA_TRUST_BUNDLE_FILE"] = "/certs/ca-bundle.crt"
	setEnvironment(t, fixture.values)

	cfg, err := loadConfig()
	require.NoError(t, err)

	assert.Equal(t, "https://manage.example", cfg.PublicBaseURL)
	assert.Equal(t, "https://agents.example", cfg.AgentURL)
	assert.Equal(t, "wss://manage.example/terminal", cfg.TerminalURL)
	assert.Equal(t, "https://hooks.example.test/power-manage?token=secret", cfg.WebhookURL)
	assert.Equal(t, fixture.values["POWER_MANAGE_ARTIFACT_PATH"], cfg.ArtifactPath)
	assert.Equal(t, fixture.values["POWER_MANAGE_BACKUP_PATH"], cfg.BackupPath)
	assert.Equal(t, fixture.values["POWER_MANAGE_DATABASE_PATH"], cfg.DatabasePath)
	assert.Equal(t, "/certs/ca.crt", cfg.CACertFile)
	assert.Equal(t, "/certs/ca.key", cfg.CAKeyFile)
	assert.Equal(t, "/certs/ca-bundle.crt", cfg.CATrustBundleFile)
	assert.Equal(t, "/certs/control.crt", cfg.AgentTLSCertFile)
	assert.Equal(t, "/certs/control.key", cfg.AgentTLSKeyFile)

	// Comma lists tolerate padding around entries but never invent one.
	assert.Equal(t, []string{"https://manage.example", "https://admin.example"}, cfg.CORSOrigins)
	assert.Equal(t, []string{"10.0.0.1", "10.0.0.2"}, cfg.TrustedProxies)
	assert.Equal(t, []string{"172.30.0.2"}, cfg.AgentProxySources)
	assert.True(t, cfg.CORSAllowAll)
	assert.Equal(t, []string{"manage.example", "admin.example"}, cfg.TerminalOrigins,
		"an unset terminal origin list follows the CORS origins")

	// Options nobody set keep their documented defaults.
	assert.Equal(t, ":8081", cfg.PublicListen)
	assert.Equal(t, ":8082", cfg.AgentListen)
	assert.Equal(t, "json", cfg.LogFormat)
	assert.Equal(t, 8760*time.Hour, cfg.CertificateValidity)
	assert.Equal(t, 90*24*time.Hour, cfg.AuditRetention)
	assert.Equal(t, 26*time.Hour, cfg.BackupMaxLag)
	assert.Empty(t, cfg.PublicTLSCertFile)
	assert.Empty(t, cfg.PublicTLSKeyFile)

	// Set options win over those defaults.
	assert.Equal(t, "debug", cfg.LogLevel)
	assert.Equal(t, 45*time.Second, cfg.HeartbeatInterval)

	assert.Equal(t, strings.Repeat("02", 32), cfg.EncryptionKey)
	assert.Equal(t, fixture.sessionKey, cfg.SessionSigningKey)
	assert.Equal(t, bytes.Repeat([]byte{1}, 32), cfg.SealingKey.Bytes())
}

func TestLoadConfigAcceptsSecretsSuppliedDirectly(t *testing.T) {
	fixture := newEnvironmentFixture(t)
	delete(fixture.values, "POWER_MANAGE_ENCRYPTION_KEY_FILE")
	delete(fixture.values, "POWER_MANAGE_SEALING_KEY_FILE")
	fixture.values["POWER_MANAGE_ENCRYPTION_KEY"] = strings.Repeat("03", 32)
	fixture.values["POWER_MANAGE_SEALING_KEY"] = strings.Repeat("04", 32)
	setEnvironment(t, fixture.values)

	cfg, err := loadConfig()
	require.NoError(t, err)
	assert.Equal(t, strings.Repeat("03", 32), cfg.EncryptionKey)
	assert.Equal(t, bytes.Repeat([]byte{4}, 32), cfg.SealingKey.Bytes())
}

func TestLoadConfigFailsClosedAndNamesTheOffendingVariable(t *testing.T) {
	tests := map[string]struct {
		mutate   func(*testing.T, environmentFixture)
		expected []string
	}{
		"unrecognized variable": {
			mutate: func(_ *testing.T, fixture environmentFixture) {
				fixture.values["POWER_MANAGE_TYPO"] = "1"
			},
			expected: []string{"POWER_MANAGE_TYPO"},
		},
		"empty list entry": {
			mutate: func(_ *testing.T, fixture environmentFixture) {
				fixture.values["POWER_MANAGE_CORS_ORIGINS"] = "https://a.example,,https://b.example"
			},
			expected: []string{"POWER_MANAGE_CORS_ORIGINS"},
		},
		"trailing list separator": {
			mutate: func(_ *testing.T, fixture environmentFixture) {
				fixture.values["POWER_MANAGE_AGENT_PROXY_SOURCES"] = "172.30.0.2,"
			},
			expected: []string{"POWER_MANAGE_AGENT_PROXY_SOURCES"},
		},
		"blank list entry": {
			mutate: func(_ *testing.T, fixture environmentFixture) {
				fixture.values["POWER_MANAGE_TERMINAL_ORIGINS"] = "manage.example,   ,admin.example"
			},
			expected: []string{"POWER_MANAGE_TERMINAL_ORIGINS"},
		},
		"invalid boolean": {
			mutate: func(_ *testing.T, fixture environmentFixture) {
				fixture.values["POWER_MANAGE_CORS_ALLOW_ALL"] = "yes-please"
			},
			expected: []string{"POWER_MANAGE_CORS_ALLOW_ALL"},
		},
		"invalid duration": {
			mutate: func(_ *testing.T, fixture environmentFixture) {
				fixture.values["POWER_MANAGE_CERTIFICATE_VALIDITY"] = "forever"
			},
			expected: []string{"POWER_MANAGE_CERTIFICATE_VALIDITY"},
		},
		"non-positive duration": {
			mutate: func(_ *testing.T, fixture environmentFixture) {
				fixture.values["POWER_MANAGE_AUDIT_RETENTION"] = "0h"
			},
			expected: []string{"POWER_MANAGE_AUDIT_RETENTION"},
		},
		"missing encryption key": {
			mutate: func(_ *testing.T, fixture environmentFixture) {
				delete(fixture.values, "POWER_MANAGE_ENCRYPTION_KEY_FILE")
			},
			expected: []string{"POWER_MANAGE_ENCRYPTION_KEY", "POWER_MANAGE_ENCRYPTION_KEY_FILE"},
		},
		"encryption key supplied twice": {
			mutate: func(_ *testing.T, fixture environmentFixture) {
				fixture.values["POWER_MANAGE_ENCRYPTION_KEY"] = strings.Repeat("05", 32)
			},
			expected: []string{"POWER_MANAGE_ENCRYPTION_KEY", "POWER_MANAGE_ENCRYPTION_KEY_FILE"},
		},
		"sealing key supplied twice": {
			mutate: func(_ *testing.T, fixture environmentFixture) {
				fixture.values["POWER_MANAGE_SEALING_KEY"] = strings.Repeat("06", 32)
			},
			expected: []string{"POWER_MANAGE_SEALING_KEY", "POWER_MANAGE_SEALING_KEY_FILE"},
		},
		"missing session signing key": {
			mutate: func(_ *testing.T, fixture environmentFixture) {
				delete(fixture.values, "POWER_MANAGE_SESSION_SIGNING_KEY_FILE")
			},
			expected: []string{"POWER_MANAGE_SESSION_SIGNING_KEY_FILE"},
		},
		"session signing key is not a PEM key": {
			mutate: func(t *testing.T, fixture environmentFixture) {
				require.NoError(t, os.WriteFile(
					fixture.values["POWER_MANAGE_SESSION_SIGNING_KEY_FILE"], []byte("not a key"), 0o600))
			},
			expected: []string{"POWER_MANAGE_SESSION_SIGNING_KEY_FILE"},
		},
		"sealing key file is group readable": {
			mutate: func(t *testing.T, fixture environmentFixture) {
				require.NoError(t, os.Chmod(fixture.values["POWER_MANAGE_SEALING_KEY_FILE"], 0o640))
			},
			expected: []string{"POWER_MANAGE_SEALING_KEY_FILE"},
		},
		"sealing key of the wrong length": {
			mutate: func(t *testing.T, fixture environmentFixture) {
				require.NoError(t, os.WriteFile(
					fixture.values["POWER_MANAGE_SEALING_KEY_FILE"], []byte(strings.Repeat("01", 16)), 0o600))
			},
			expected: []string{"POWER_MANAGE_SEALING_KEY_FILE"},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newEnvironmentFixture(t)
			test.mutate(t, fixture)
			setEnvironment(t, fixture.values)

			cfg, err := loadConfig()
			require.Error(t, err)
			assert.Nil(t, cfg)
			for _, expected := range test.expected {
				assert.ErrorContains(t, err, expected)
			}
		})
	}
}

func TestLoadConfigKeepsExistingValidationSemantics(t *testing.T) {
	tests := map[string]struct {
		mutate   func(environmentFixture)
		expected string
	}{
		"listeners must differ": {
			mutate: func(fixture environmentFixture) {
				fixture.values["POWER_MANAGE_PUBLIC_LISTEN"] = ":9000"
				fixture.values["POWER_MANAGE_AGENT_LISTEN"] = ":9000"
			},
			expected: "must be distinct",
		},
		"agent proxy sources are required": {
			mutate: func(fixture environmentFixture) {
				delete(fixture.values, "POWER_MANAGE_AGENT_PROXY_SOURCES")
			},
			expected: "isolated reverse proxy network",
		},
		"agent proxy sources must be addresses": {
			mutate: func(fixture environmentFixture) {
				fixture.values["POWER_MANAGE_AGENT_PROXY_SOURCES"] = "not-an-address"
			},
			expected: "invalid address",
		},
		"public base URL must be https": {
			mutate: func(fixture environmentFixture) {
				fixture.values["POWER_MANAGE_PUBLIC_BASE_URL"] = "http://manage.example"
			},
			expected: "public_base_url",
		},
		"terminal URL must end at /terminal": {
			mutate: func(fixture environmentFixture) {
				fixture.values["POWER_MANAGE_TERMINAL_URL"] = "wss://manage.example/other"
			},
			expected: "terminal_url",
		},
		"CORS origins must be bare origins": {
			mutate: func(fixture environmentFixture) {
				fixture.values["POWER_MANAGE_CORS_ORIGINS"] = "https://manage.example/app"
			},
			expected: "invalid CORS origin",
		},
		"public TLS certificate and key travel together": {
			mutate: func(fixture environmentFixture) {
				fixture.values["POWER_MANAGE_PUBLIC_TLS_CERT_FILE"] = "/certs/public.crt"
			},
			expected: "must be set together",
		},
		"CA certificate is required": {
			mutate: func(fixture environmentFixture) {
				delete(fixture.values, "POWER_MANAGE_CA_CERT_FILE")
			},
			expected: "ca_cert_file is required",
		},
		"artifact path must exist": {
			mutate: func(fixture environmentFixture) {
				fixture.values["POWER_MANAGE_ARTIFACT_PATH"] = "/nonexistent/power-manage-artifacts"
			},
			expected: "artifact_path",
		},
		"database path must be absolute": {
			mutate: func(fixture environmentFixture) {
				fixture.values["POWER_MANAGE_DATABASE_PATH"] = "control.db"
			},
			expected: "database_path must be an absolute file path",
		},
		"webhook URL must be https": {
			mutate: func(fixture environmentFixture) {
				fixture.values["POWER_MANAGE_WEBHOOK_URL"] = "http://hooks.example.test"
			},
			expected: "webhook_url",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newEnvironmentFixture(t)
			test.mutate(fixture)
			setEnvironment(t, fixture.values)

			cfg, err := loadConfig()
			require.Error(t, err)
			assert.Nil(t, cfg)
			assert.ErrorContains(t, err, test.expected)
		})
	}
}

// TestLoadConfigErrorsNeverEchoSecretValues holds the logging and diagnostics
// boundary: a rejected secret is reported by the variable that carried it.
func TestLoadConfigErrorsNeverEchoSecretValues(t *testing.T) {
	const sealingSecret = "0a1b2c3d"
	fixture := newEnvironmentFixture(t)
	delete(fixture.values, "POWER_MANAGE_SEALING_KEY_FILE")
	fixture.values["POWER_MANAGE_SEALING_KEY"] = sealingSecret
	setEnvironment(t, fixture.values)

	cfg, err := loadConfig()
	require.Error(t, err)
	assert.Nil(t, cfg)
	assert.ErrorContains(t, err, "POWER_MANAGE_SEALING_KEY")
	assert.NotContains(t, err.Error(), sealingSecret)
}

// TestEveryConfigOptionDeclaresItsVariable keeps the recognized set derived
// from the option declarations. A new option without a variable, or one whose
// variable does not follow POWER_MANAGE_<UPPER_SNAKE>, fails here instead of
// becoming silently unconfigurable or unrecognized.
func TestEveryConfigOptionDeclaresItsVariable(t *testing.T) {
	fields := reflect.VisibleFields(reflect.TypeOf(configEnvironment{}))
	require.NotEmpty(t, fields, "the option table must declare at least one option")

	declared := declaredOptions()
	require.Len(t, declared, len(fields), "every option needs its own distinct variable")
	for _, field := range fields {
		expected := optionPrefix + upperSnake(field.Name)
		assert.Equal(t, expected, field.Tag.Get("env"),
			"option %s must declare the variable derived from its name", field.Name)
		assert.Contains(t, declared, expected)
	}
}

// upperSnake derives the expected variable suffix from a field name
// independently of the struct tags, so a mistyped tag cannot pass the guard.
func upperSnake(name string) string {
	runes := []rune(name)
	var builder strings.Builder
	for index, current := range runes {
		if index > 0 && unicode.IsUpper(current) {
			var next rune
			if index+1 < len(runes) {
				next = runes[index+1]
			}
			if unicode.IsLower(runes[index-1]) || unicode.IsLower(next) {
				builder.WriteRune('_')
			}
		}
		builder.WriteRune(unicode.ToUpper(current))
	}
	return builder.String()
}

func TestParseCommandAcceptsSubcommandsAndRejectsEverythingElse(t *testing.T) {
	for name, args := range map[string][]string{
		"serve":           {},
		"bootstrap-admin": {"bootstrap-admin"},
		"backup-status":   {"backup-status"},
	} {
		command, err := parseCommand(args)
		require.NoError(t, err)
		assert.Equal(t, name, command)
	}

	const hint = " (accepted commands: bootstrap-admin, backup-status)"
	for message, args := range map[string][]string{
		"unexpected arguments: -config /etc/power-manage/control.json" + hint: {"-config", "/etc/power-manage/control.json"},
		"unexpected arguments: --help" + hint:                                 {"--help"},
		"unexpected arguments: serve" + hint:                                  {"serve"},
		"unexpected arguments: extra":                                         {"bootstrap-admin", "extra"},
		"unexpected arguments: -config /etc/power-manage/control.json":        {"backup-status", "-config", "/etc/power-manage/control.json"},
	} {
		command, err := parseCommand(args)
		assert.EqualError(t, err, message, "%v must be rejected", args)
		assert.Empty(t, command)
	}
}

// TestLoadConfigRefusesAnArchiveOnTheDatabaseFilesystem holds the enforced
// half of "the audit chain's head is anchored off-host": an archive sharing a
// mount with the database it is evidence for is not off-host, and whoever can
// rewrite one can rewrite both. This case uses the REAL filesystem probe —
// two directories under one temp dir genuinely are one mount — so it fails if
// the check is removed, weakened, or made to depend only on the test seam.
func TestLoadConfigRefusesAnArchiveOnTheDatabaseFilesystem(t *testing.T) {
	fixture := newEnvironmentFixture(t)
	useRealFilesystemProbe(t)
	setEnvironment(t, fixture.values)

	cfg, err := loadConfig()
	require.Error(t, err)
	assert.Nil(t, cfg)
	assert.ErrorContains(t, err, fixture.values["POWER_MANAGE_BACKUP_PATH"])
	assert.ErrorContains(t, err, filepath.Dir(fixture.values["POWER_MANAGE_DATABASE_PATH"]))
	assert.ErrorContains(t, err, "same filesystem")
	assert.ErrorContains(t, err, "separate mount",
		"the operator must be told what to do, not only that something is wrong")
}

// TestLoadConfigAcceptsAnArchiveOnADistinctFilesystem is the positive control:
// the refusal above must be about the shared mount and nothing else.
func TestLoadConfigAcceptsAnArchiveOnADistinctFilesystem(t *testing.T) {
	fixture := newEnvironmentFixture(t)
	setEnvironment(t, fixture.values)

	cfg, err := loadConfig()
	require.NoError(t, err)
	assert.Equal(t, fixture.values["POWER_MANAGE_BACKUP_PATH"], cfg.BackupPath)
}

// TestFilesystemDeviceIDIdentifiesOneMount pins what that decision rests on.
// A probe that failed open — reporting distinct identifiers for one mount, or
// swallowing a stat error — would make the refusal above unreachable in
// production while the seam-driven cases stayed green.
func TestFilesystemDeviceIDIdentifiesOneMount(t *testing.T) {
	directory := t.TempDir()
	first := filepath.Join(directory, "first")
	second := filepath.Join(directory, "second")
	require.NoError(t, os.Mkdir(first, 0o700))
	require.NoError(t, os.Mkdir(second, 0o700))

	firstID, err := filesystemDeviceID(first)
	require.NoError(t, err)
	secondID, err := filesystemDeviceID(second)
	require.NoError(t, err)
	assert.Equal(t, firstID, secondID, "two directories in one temp dir share a filesystem")

	_, err = filesystemDeviceID(filepath.Join(directory, "absent"))
	assert.Error(t, err, "an unstattable path must fail closed rather than read as a distinct mount")
}

func TestValidateConfigRequiresWritableDataDirectories(t *testing.T) {
	file := filepath.Join(t.TempDir(), "not-a-directory")
	require.NoError(t, os.WriteFile(file, []byte("x"), 0o600))

	err := validateWritableDirectory("artifact_path", file)
	assert.ErrorContains(t, err, "must be a directory")
	assert.ErrorContains(t, validateWritableDirectory("backup_path", ""), "is required")
}

func TestValidateDatabasePathRequiresAnAbsoluteFileInAWritableDirectory(t *testing.T) {
	directory := t.TempDir()
	assert.NoError(t, validateDatabasePath(filepath.Join(directory, "control.db")))
	assert.ErrorContains(t, validateDatabasePath("control.db"), "absolute")
	assert.ErrorContains(t, validateDatabasePath(directory), "regular file")
}

func TestSecretFileReaderRejectsLooseFiles(t *testing.T) {
	directory := t.TempDir()
	loose := filepath.Join(directory, "loose.key")
	require.NoError(t, os.WriteFile(loose, []byte("secret"), 0o644))
	_, err := readSecretFile(loose)
	assert.ErrorContains(t, err, "group/world accessible")

	_, err = readSecretFile("")
	assert.ErrorContains(t, err, "required")

	_, err = readSecretFile(directory)
	assert.ErrorContains(t, err, "small regular file")
}
