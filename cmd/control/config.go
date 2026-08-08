package main

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/manchtools/power-manage/server/internal/enrollment"
	"github.com/manchtools/power-manage/server/internal/webhook"
)

const (
	// optionPrefix marks the variables control owns. Every variable carrying
	// it must be declared on configEnvironment, so a misspelled variable fails
	// startup instead of leaving the option it meant to set at its default.
	optionPrefix   = "POWER_MANAGE_"
	maxSecretBytes = 64 << 10
)

// configEnviron reports the process environment. It is a package variable so
// tests can drive the loader without inheriting POWER_MANAGE_ variables that
// already exist in the surrounding shell.
var configEnviron = os.Environ

// filesystemIDOf reports which filesystem holds a path. It is a package
// variable for the same reason configEnviron is: creating a second real
// filesystem needs root, so a test cannot otherwise exercise the accepting
// side of the separation check the loader enforces below.
var filesystemIDOf = filesystemDeviceID

// configEnvironment declares every recognized option exactly once: the tag
// names its variable and the field type selects its parser. The recognized set
// is derived from these declarations rather than from a second list.
type configEnvironment struct {
	PublicListen          string        `env:"POWER_MANAGE_PUBLIC_LISTEN"`
	AgentListen           string        `env:"POWER_MANAGE_AGENT_LISTEN"`
	PublicBaseURL         string        `env:"POWER_MANAGE_PUBLIC_BASE_URL"`
	AgentURL              string        `env:"POWER_MANAGE_AGENT_URL"`
	TerminalURL           string        `env:"POWER_MANAGE_TERMINAL_URL"`
	CORSOrigins           []string      `env:"POWER_MANAGE_CORS_ORIGINS"`
	TerminalOrigins       []string      `env:"POWER_MANAGE_TERMINAL_ORIGINS"`
	TrustedProxies        []string      `env:"POWER_MANAGE_TRUSTED_PROXIES"`
	AgentProxySources     []string      `env:"POWER_MANAGE_AGENT_PROXY_SOURCES"`
	CORSAllowAll          bool          `env:"POWER_MANAGE_CORS_ALLOW_ALL"`
	LogLevel              string        `env:"POWER_MANAGE_LOG_LEVEL"`
	LogFormat             string        `env:"POWER_MANAGE_LOG_FORMAT"`
	CertificateValidity   time.Duration `env:"POWER_MANAGE_CERTIFICATE_VALIDITY"`
	HeartbeatInterval     time.Duration `env:"POWER_MANAGE_HEARTBEAT_INTERVAL"`
	AuditRetention        time.Duration `env:"POWER_MANAGE_AUDIT_RETENTION"`
	ArtifactPath          string        `env:"POWER_MANAGE_ARTIFACT_PATH"`
	BackupPath            string        `env:"POWER_MANAGE_BACKUP_PATH"`
	BackupMaxLag          time.Duration `env:"POWER_MANAGE_BACKUP_MAX_LAG"`
	WebhookURL            string        `env:"POWER_MANAGE_WEBHOOK_URL"`
	CACertFile            string        `env:"POWER_MANAGE_CA_CERT_FILE"`
	CAKeyFile             string        `env:"POWER_MANAGE_CA_KEY_FILE"`
	CATrustBundleFile     string        `env:"POWER_MANAGE_CA_TRUST_BUNDLE_FILE"`
	AgentTLSCertFile      string        `env:"POWER_MANAGE_AGENT_TLS_CERT_FILE"`
	AgentTLSKeyFile       string        `env:"POWER_MANAGE_AGENT_TLS_KEY_FILE"`
	PublicTLSCertFile     string        `env:"POWER_MANAGE_PUBLIC_TLS_CERT_FILE"`
	PublicTLSKeyFile      string        `env:"POWER_MANAGE_PUBLIC_TLS_KEY_FILE"`
	DatabasePath          string        `env:"POWER_MANAGE_DATABASE_PATH"`
	EncryptionKey         string        `env:"POWER_MANAGE_ENCRYPTION_KEY"`
	EncryptionKeyFile     string        `env:"POWER_MANAGE_ENCRYPTION_KEY_FILE"`
	SessionSigningKeyFile string        `env:"POWER_MANAGE_SESSION_SIGNING_KEY_FILE"`
	SealingKey            string        `env:"POWER_MANAGE_SEALING_KEY"`
	SealingKeyFile        string        `env:"POWER_MANAGE_SEALING_KEY_FILE"`
}

type Config struct {
	PublicListen        string
	AgentListen         string
	PublicBaseURL       string
	AgentURL            string
	TerminalURL         string
	CORSOrigins         []string
	TerminalOrigins     []string
	TrustedProxies      []string
	AgentProxySources   []string
	CORSAllowAll        bool
	LogLevel            string
	LogFormat           string
	CertificateValidity time.Duration
	HeartbeatInterval   time.Duration
	AuditRetention      time.Duration
	ArtifactPath        string
	BackupPath          string
	BackupMaxLag        time.Duration
	WebhookURL          string
	CACertFile          string
	CAKeyFile           string
	CATrustBundleFile   string
	AgentTLSCertFile    string
	AgentTLSKeyFile     string
	PublicTLSCertFile   string
	PublicTLSKeyFile    string
	DatabasePath        string
	EncryptionKey       string
	SessionSigningKey   ed25519.PrivateKey
	SealingKey          *ecdh.PrivateKey
}

// loadConfig builds the control configuration from the POWER_MANAGE_
// environment. There is no configuration file.
func loadConfig() (*Config, error) {
	document, err := readEnvironment(configEnviron())
	if err != nil {
		return nil, err
	}

	encryptionKey, _, err := loadSecret(
		"POWER_MANAGE_ENCRYPTION_KEY", document.EncryptionKey,
		"POWER_MANAGE_ENCRYPTION_KEY_FILE", document.EncryptionKeyFile)
	if err != nil {
		return nil, err
	}
	sessionKey, err := loadEd25519PrivateKey(document.SessionSigningKeyFile)
	if err != nil {
		return nil, fmt.Errorf("POWER_MANAGE_SESSION_SIGNING_KEY_FILE: %w", err)
	}
	sealingSecret, sealingVariable, err := loadSecret(
		"POWER_MANAGE_SEALING_KEY", document.SealingKey,
		"POWER_MANAGE_SEALING_KEY_FILE", document.SealingKeyFile)
	if err != nil {
		return nil, err
	}
	sealingKey, err := parseX25519PrivateKey(sealingSecret)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", sealingVariable, err)
	}

	cfg := &Config{
		PublicListen: document.PublicListen, AgentListen: document.AgentListen,
		PublicBaseURL: document.PublicBaseURL, AgentURL: document.AgentURL, TerminalURL: document.TerminalURL,
		CORSOrigins: document.CORSOrigins, TerminalOrigins: document.TerminalOrigins,
		TrustedProxies: document.TrustedProxies, AgentProxySources: document.AgentProxySources,
		CORSAllowAll: document.CORSAllowAll,
		LogLevel:     document.LogLevel, LogFormat: document.LogFormat,
		CertificateValidity: document.CertificateValidity, HeartbeatInterval: document.HeartbeatInterval,
		AuditRetention:    document.AuditRetention,
		ArtifactPath:      document.ArtifactPath,
		BackupPath:        document.BackupPath,
		BackupMaxLag:      document.BackupMaxLag,
		WebhookURL:        document.WebhookURL,
		CACertFile:        document.CACertFile,
		CAKeyFile:         document.CAKeyFile,
		CATrustBundleFile: document.CATrustBundleFile,
		AgentTLSCertFile:  document.AgentTLSCertFile,
		AgentTLSKeyFile:   document.AgentTLSKeyFile,
		PublicTLSCertFile: document.PublicTLSCertFile,
		PublicTLSKeyFile:  document.PublicTLSKeyFile,
		DatabasePath:      document.DatabasePath, EncryptionKey: encryptionKey,
		SessionSigningKey: sessionKey, SealingKey: sealingKey,
	}
	if len(cfg.TerminalOrigins) == 0 {
		cfg.TerminalOrigins = originHosts(cfg.CORSOrigins)
	}
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// readEnvironment resolves the declared options from the raw environment
// entries. Unrecognized POWER_MANAGE_ variables are rejected before anything
// is parsed, and only variable names are reported because values may be
// secrets.
func readEnvironment(entries []string) (configEnvironment, error) {
	document := defaultEnvironment()
	declared := declaredOptions()
	values := make(map[string]string, len(declared))
	for _, entry := range entries {
		name, value, separated := strings.Cut(entry, "=")
		if !separated || !strings.HasPrefix(name, optionPrefix) {
			continue
		}
		if _, recognized := declared[name]; !recognized {
			return document, fmt.Errorf("unrecognized configuration variable %s", name)
		}
		values[name] = value
	}
	if err := applyEnvironment(&document, values); err != nil {
		return document, err
	}
	return document, nil
}

// declaredOptions is the recognized variable set, derived from the
// configEnvironment declarations so that declaring an option extends the
// fail-closed guard with it.
func declaredOptions() map[string]struct{} {
	fields := reflect.VisibleFields(reflect.TypeOf(configEnvironment{}))
	declared := make(map[string]struct{}, len(fields))
	for _, field := range fields {
		if name := field.Tag.Get("env"); name != "" {
			declared[name] = struct{}{}
		}
	}
	return declared
}

// applyEnvironment overwrites the defaults with the variables that carry a
// value. Malformed values fail closed and name their variable.
func applyEnvironment(document *configEnvironment, values map[string]string) error {
	fields := reflect.ValueOf(document).Elem()
	for _, field := range reflect.VisibleFields(fields.Type()) {
		name := field.Tag.Get("env")
		if name == "" {
			return fmt.Errorf("option %s declares no environment variable", field.Name)
		}
		// A blank variable leaves a scalar at its default; a blank list option
		// is an empty list, which is what an unset list means too.
		raw := strings.TrimSpace(values[name])
		if raw == "" && field.Type.Kind() != reflect.Slice {
			continue
		}
		target := fields.FieldByIndex(field.Index)
		switch target.Interface().(type) {
		case string:
			target.SetString(raw)
		case []string:
			list, err := parseList(name, raw)
			if err != nil {
				return err
			}
			target.Set(reflect.ValueOf(list))
		case bool:
			parsed, err := strconv.ParseBool(raw)
			if err != nil {
				return fmt.Errorf("%s must be a boolean", name)
			}
			target.SetBool(parsed)
		case time.Duration:
			parsed, err := time.ParseDuration(raw)
			if err != nil || parsed <= 0 {
				return fmt.Errorf("%s must be a positive duration", name)
			}
			target.SetInt(int64(parsed))
		default:
			return fmt.Errorf("option %s has unsupported type %s", field.Name, field.Type)
		}
	}
	return nil
}

// parseList splits a comma-separated option and trims each entry. An empty
// entry is a typo rather than an intent to configure nothing, so it fails
// closed instead of being dropped silently.
func parseList(name, raw string) ([]string, error) {
	if raw == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	list := make([]string, 0, len(parts))
	for _, part := range parts {
		entry := strings.TrimSpace(part)
		if entry == "" {
			return nil, fmt.Errorf("%s must not contain an empty entry", name)
		}
		list = append(list, entry)
	}
	return list, nil
}

func defaultEnvironment() configEnvironment {
	return configEnvironment{
		PublicListen:        ":8081",
		AgentListen:         ":8082",
		LogLevel:            "info",
		LogFormat:           "json",
		CertificateValidity: 8760 * time.Hour,
		HeartbeatInterval:   30 * time.Second,
		AuditRetention:      2160 * time.Hour,
		BackupMaxLag:        26 * time.Hour,
		DatabasePath:        "/var/lib/power-manage/control.db",
	}
}

func validateConfig(cfg *Config) error {
	if cfg.PublicListen == "" || cfg.AgentListen == "" || cfg.PublicListen == cfg.AgentListen {
		return errors.New("public_listen and agent_listen must be distinct")
	}
	if len(cfg.AgentProxySources) == 0 {
		return errors.New("agent_proxy_sources must name the isolated reverse proxy network")
	}
	for _, source := range cfg.AgentProxySources {
		if net.ParseIP(source) != nil {
			continue
		}
		if _, _, err := net.ParseCIDR(source); err != nil {
			return fmt.Errorf("agent_proxy_sources contains invalid address %q", source)
		}
	}
	if err := validateHTTPSURL("public_base_url", cfg.PublicBaseURL); err != nil {
		return err
	}
	if err := enrollment.ValidateControlURL(cfg.AgentURL); err != nil {
		return fmt.Errorf("agent_url: %w", err)
	}
	terminalURL, err := url.Parse(cfg.TerminalURL)
	if err != nil || terminalURL.Scheme != "wss" || terminalURL.Host == "" || terminalURL.User != nil ||
		terminalURL.Fragment != "" || terminalURL.RawQuery != "" || terminalURL.Path != "/terminal" {
		return errors.New("terminal_url must be an absolute wss URL ending at /terminal without credentials, query, or fragment")
	}
	for _, origin := range cfg.CORSOrigins {
		parsed, err := url.Parse(origin)
		if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" ||
			parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
			return fmt.Errorf("invalid CORS origin %q", origin)
		}
	}
	if cfg.EncryptionKey == "" {
		return errors.New("encryption key is required")
	}
	if err := validateDatabasePath(cfg.DatabasePath); err != nil {
		return err
	}
	if err := validateWritableDirectory("artifact_path", cfg.ArtifactPath); err != nil {
		return err
	}
	if err := validateWritableDirectory("backup_path", cfg.BackupPath); err != nil {
		return err
	}
	if err := validateArchiveIsolation(cfg.DatabasePath, cfg.BackupPath); err != nil {
		if !archiveIsolationRelaxed() {
			return err
		}
		fmt.Fprintln(os.Stderr, "control: DEVELOPMENT BUILD, audit archive separation not enforced:", err)
	}
	if _, err := webhook.New(cfg.WebhookURL); err != nil {
		return err
	}
	for name, path := range map[string]string{
		"ca_cert_file": cfg.CACertFile, "ca_key_file": cfg.CAKeyFile,
		"agent_tls_cert_file": cfg.AgentTLSCertFile, "agent_tls_key_file": cfg.AgentTLSKeyFile,
	} {
		if path == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	if (cfg.PublicTLSCertFile == "") != (cfg.PublicTLSKeyFile == "") {
		return errors.New("public_tls_cert_file and public_tls_key_file must be set together")
	}
	if len(cfg.SessionSigningKey) != ed25519.PrivateKeySize || cfg.SealingKey == nil {
		return errors.New("session and sealing private keys are required")
	}
	return nil
}

func validateDatabasePath(path string) error {
	if path == "" || !filepath.IsAbs(path) {
		return errors.New("database_path must be an absolute file path")
	}
	info, err := os.Stat(path)
	if err == nil {
		if !info.Mode().IsRegular() {
			return fmt.Errorf("database_path %q must be a regular file", path)
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("database_path %q: %w", path, err)
	}
	return validateWritableDirectory("database_path parent", filepath.Dir(path))
}

// validateArchiveIsolation refuses to start control when the audit archive
// shares a filesystem with the database it is evidence for.
//
// The archive holds the anchors that authenticate the audit chain's head and
// the prefixes retention deleted live rows in exchange for. Both stop being
// evidence the moment one actor can write to the database and the archive at
// once: the same root, the same disk failure, or the same ransomware pass
// takes the record and its proof together. Documentation states that the
// chain's head is anchored separately, and an operator has to be able to say
// that to an auditor, so it is a boot condition rather than a recommendation.
//
// Comparison is by filesystem, which is what a mount boundary actually is.
// It is a floor, not a guarantee of remoteness: a second local disk passes
// while sharing a machine. Anything stronger — a different host, different
// credentials, immutable object storage — is the operator's to provide, and
// this refuses the one case the process can prove is wrong on its own.
func validateArchiveIsolation(databasePath, archivePath string) error {
	databaseProbe := databasePath
	if _, err := os.Stat(databasePath); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("database_path %q: %w", databasePath, err)
		}
		databaseProbe = filepath.Dir(databasePath)
	}
	databaseFilesystem, err := filesystemIDOf(databaseProbe)
	if err != nil {
		return fmt.Errorf("database_path %q: %w", databaseProbe, err)
	}
	archiveFilesystem, err := filesystemIDOf(archivePath)
	if err != nil {
		return fmt.Errorf("backup_path %q: %w", archivePath, err)
	}
	if databaseFilesystem != archiveFilesystem {
		return nil
	}
	return fmt.Errorf(
		"backup_path %q is on the same filesystem as the database at %q: the audit archive holds separately stored "+
			"evidence for that database and must be a separate mount, ideally remote storage under different "+
			"credentials, so that losing or tampering with one cannot silently take the other with it; mount a "+
			"distinct filesystem and point POWER_MANAGE_BACKUP_PATH at it",
		archivePath, databaseProbe)
}

func validateWritableDirectory(name, path string) error {
	if path == "" {
		return fmt.Errorf("%s is required", name)
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("%s %q: %w", name, path, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s %q must be a directory", name, path)
	}
	probe, err := os.CreateTemp(path, ".power-manage-write-probe-*")
	if err != nil {
		return fmt.Errorf("%s %q is not writable: %w", name, path, err)
	}
	probePath := probe.Name()
	if err := probe.Close(); err != nil {
		_ = os.Remove(probePath)
		return fmt.Errorf("%s %q write probe: %w", name, path, err)
	}
	if err := os.Remove(probePath); err != nil {
		return fmt.Errorf("%s %q remove write probe: %w", name, path, err)
	}
	return nil
}

func validateHTTPSURL(name, raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
		parsed.Fragment != "" || parsed.RawQuery != "" {
		return fmt.Errorf("%s must be an absolute https URL without credentials or fragment", name)
	}
	return nil
}

func originHosts(origins []string) []string {
	hosts := make([]string, 0, len(origins))
	seen := make(map[string]struct{}, len(origins))
	for _, raw := range origins {
		parsed, err := url.Parse(raw)
		if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" {
			continue
		}
		if _, exists := seen[parsed.Host]; exists {
			continue
		}
		seen[parsed.Host] = struct{}{}
		hosts = append(hosts, parsed.Host)
	}
	return hosts
}

// loadSecret resolves a secret from either its direct value variable or its
// file variable and reports which one supplied it. Naming both is a
// configuration mistake rather than a precedence question, so it fails closed.
// Errors name variables only; secret values are never echoed.
func loadSecret(valueVariable, value, fileVariable, file string) (string, string, error) {
	switch {
	case value != "" && file != "":
		return "", "", fmt.Errorf("%s and %s must not both be set", valueVariable, fileVariable)
	case value != "":
		return value, valueVariable, nil
	case file == "":
		return "", "", fmt.Errorf("%s or %s is required", valueVariable, fileVariable)
	}
	data, err := readSecretFile(file)
	if err != nil {
		return "", "", fmt.Errorf("%s: %w", fileVariable, err)
	}
	secret := strings.TrimSpace(string(data))
	if secret == "" {
		return "", "", fmt.Errorf("%s names an empty secret file", fileVariable)
	}
	return secret, fileVariable, nil
}

func readSecretFile(path string) ([]byte, error) {
	if path == "" {
		return nil, errors.New("secret file path is required")
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxSecretBytes {
		return nil, errors.New("secret must be a small regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("secret file %q must not be group/world accessible", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func loadEd25519PrivateKey(path string) (ed25519.PrivateKey, error) {
	data, err := readSecretFile(path)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(data)
	if block == nil || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("expected one PEM private key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok || len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("session signing key must be Ed25519 PKCS#8")
	}
	return append(ed25519.PrivateKey(nil), key...), nil
}

// parseX25519PrivateKey decodes the sealing key material. The encoded text is
// secret, so decoding failures describe the expected shape and never the
// value.
func parseX25519PrivateKey(text string) (*ecdh.PrivateKey, error) {
	var raw []byte
	for _, decode := range []func(string) ([]byte, error){hex.DecodeString, base64.RawStdEncoding.DecodeString, base64.StdEncoding.DecodeString} {
		decoded, decodeErr := decode(text)
		if decodeErr == nil && len(decoded) == 32 {
			raw = decoded
			break
		}
	}
	if len(raw) != 32 {
		return nil, errors.New("sealing key must encode exactly 32 X25519 private-key bytes")
	}
	key, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return nil, err
	}
	return key, nil
}
