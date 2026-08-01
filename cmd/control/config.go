package main

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/manchtools/power-manage/server/internal/enrollment"
)

const (
	defaultConfigPath = "/etc/power-manage/control.json"
	maxConfigBytes    = 1 << 20
	maxSecretBytes    = 64 << 10
)

type configDocument struct {
	PublicListen          string   `json:"public_listen"`
	AgentListen           string   `json:"agent_listen"`
	PublicBaseURL         string   `json:"public_base_url"`
	AgentURL              string   `json:"agent_url"`
	TerminalURL           string   `json:"terminal_url"`
	CORSOrigins           []string `json:"cors_origins"`
	TerminalOrigins       []string `json:"terminal_origins"`
	TrustedProxies        []string `json:"trusted_proxies"`
	CORSAllowAll          bool     `json:"cors_allow_all"`
	LogLevel              string   `json:"log_level"`
	LogFormat             string   `json:"log_format"`
	CertificateValidity   string   `json:"certificate_validity"`
	HeartbeatInterval     string   `json:"heartbeat_interval"`
	CACertFile            string   `json:"ca_cert_file"`
	CAKeyFile             string   `json:"ca_key_file"`
	AgentTLSCertFile      string   `json:"agent_tls_cert_file"`
	AgentTLSKeyFile       string   `json:"agent_tls_key_file"`
	PublicTLSCertFile     string   `json:"public_tls_cert_file"`
	PublicTLSKeyFile      string   `json:"public_tls_key_file"`
	DatabaseURLFile       string   `json:"database_url_file"`
	EncryptionKeyFile     string   `json:"encryption_key_file"`
	SessionSigningKeyFile string   `json:"session_signing_key_file"`
	SealingKeyFile        string   `json:"sealing_key_file"`
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
	CORSAllowAll        bool
	LogLevel            string
	LogFormat           string
	CertificateValidity time.Duration
	HeartbeatInterval   time.Duration
	CACertFile          string
	CAKeyFile           string
	AgentTLSCertFile    string
	AgentTLSKeyFile     string
	PublicTLSCertFile   string
	PublicTLSKeyFile    string
	DatabaseURL         string
	EncryptionKey       string
	SessionSigningKey   ed25519.PrivateKey
	SealingKey          *ecdh.PrivateKey
}

func loadConfig(args []string) (*Config, error) {
	flags := flag.NewFlagSet("control", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	defaultPath := os.Getenv("POWER_MANAGE_CONFIG_FILE")
	if defaultPath == "" {
		defaultPath = defaultConfigPath
	}
	path := flags.String("config", defaultPath, "path to control.json")
	if err := flags.Parse(args); err != nil {
		return nil, err
	}
	if flags.NArg() != 0 {
		return nil, fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}

	var document configDocument
	if err := decodeConfigFile(*path, &document); err != nil {
		return nil, err
	}
	applyDefaults(&document)

	databaseURL, err := loadSecret("POWER_MANAGE_DATABASE_URL", "POWER_MANAGE_DATABASE_URL_FILE", document.DatabaseURLFile)
	if err != nil {
		return nil, fmt.Errorf("database URL: %w", err)
	}
	encryptionKey, err := loadSecret("POWER_MANAGE_ENCRYPTION_KEY", "POWER_MANAGE_ENCRYPTION_KEY_FILE", document.EncryptionKeyFile)
	if err != nil {
		return nil, fmt.Errorf("encryption key: %w", err)
	}
	sessionKeyPath := pathOverride("POWER_MANAGE_SESSION_SIGNING_KEY_FILE", document.SessionSigningKeyFile)
	sessionKey, err := loadEd25519PrivateKey(sessionKeyPath)
	if err != nil {
		return nil, fmt.Errorf("session signing key: %w", err)
	}
	sealingKeyPath := pathOverride("POWER_MANAGE_SEALING_KEY_FILE", document.SealingKeyFile)
	sealingKey, err := loadX25519PrivateKey(sealingKeyPath)
	if err != nil {
		return nil, fmt.Errorf("sealing key: %w", err)
	}

	certificateValidity, err := time.ParseDuration(document.CertificateValidity)
	if err != nil || certificateValidity <= 0 {
		return nil, errors.New("certificate_validity must be a positive duration")
	}
	heartbeatInterval, err := time.ParseDuration(document.HeartbeatInterval)
	if err != nil || heartbeatInterval <= 0 {
		return nil, errors.New("heartbeat_interval must be a positive duration")
	}
	cfg := &Config{
		PublicListen: document.PublicListen, AgentListen: document.AgentListen,
		PublicBaseURL: document.PublicBaseURL, AgentURL: document.AgentURL, TerminalURL: document.TerminalURL,
		CORSOrigins:     append([]string(nil), document.CORSOrigins...),
		TerminalOrigins: append([]string(nil), document.TerminalOrigins...),
		TrustedProxies:  append([]string(nil), document.TrustedProxies...), CORSAllowAll: document.CORSAllowAll,
		LogLevel: document.LogLevel, LogFormat: document.LogFormat,
		CertificateValidity: certificateValidity, HeartbeatInterval: heartbeatInterval,
		CACertFile:        document.CACertFile,
		CAKeyFile:         pathOverride("POWER_MANAGE_CA_KEY_FILE", document.CAKeyFile),
		AgentTLSCertFile:  document.AgentTLSCertFile,
		AgentTLSKeyFile:   pathOverride("POWER_MANAGE_AGENT_TLS_KEY_FILE", document.AgentTLSKeyFile),
		PublicTLSCertFile: document.PublicTLSCertFile,
		PublicTLSKeyFile:  pathOverride("POWER_MANAGE_PUBLIC_TLS_KEY_FILE", document.PublicTLSKeyFile),
		DatabaseURL:       databaseURL, EncryptionKey: encryptionKey,
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

func decodeConfigFile(path string, target *configDocument) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat config %q: %w", path, err)
	}
	if !info.Mode().IsRegular() || info.Size() > maxConfigBytes {
		return fmt.Errorf("config %q must be a regular file no larger than %d bytes", path, maxConfigBytes)
	}
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open config %q: %w", path, err)
	}
	defer func() { _ = file.Close() }()
	decoder := json.NewDecoder(io.LimitReader(file, maxConfigBytes+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode config %q: %w", path, err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return fmt.Errorf("decode config %q: trailing content", path)
	}
	return nil
}

func applyDefaults(document *configDocument) {
	if document.PublicListen == "" {
		document.PublicListen = ":8081"
	}
	if document.AgentListen == "" {
		document.AgentListen = ":8082"
	}
	if document.LogLevel == "" {
		document.LogLevel = "info"
	}
	if document.LogFormat == "" {
		document.LogFormat = "json"
	}
	if document.CertificateValidity == "" {
		document.CertificateValidity = "8760h"
	}
	if document.HeartbeatInterval == "" {
		document.HeartbeatInterval = "30s"
	}
}

func validateConfig(cfg *Config) error {
	if cfg.PublicListen == "" || cfg.AgentListen == "" || cfg.PublicListen == cfg.AgentListen {
		return errors.New("public_listen and agent_listen must be distinct")
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
	if cfg.DatabaseURL == "" || cfg.EncryptionKey == "" {
		return errors.New("database and encryption secrets are required")
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

func pathOverride(environment, configured string) string {
	if value := strings.TrimSpace(os.Getenv(environment)); value != "" {
		return value
	}
	return configured
}

func loadSecret(valueEnvironment, fileEnvironment, configuredFile string) (string, error) {
	if value := strings.TrimSpace(os.Getenv(valueEnvironment)); value != "" {
		return value, nil
	}
	path := pathOverride(fileEnvironment, configuredFile)
	if path == "" {
		return "", errors.New("secret file is required")
	}
	data, err := readSecretFile(path)
	if err != nil {
		return "", err
	}
	value := strings.TrimSpace(string(data))
	if value == "" {
		return "", errors.New("secret file is empty")
	}
	return value, nil
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

func loadX25519PrivateKey(path string) (*ecdh.PrivateKey, error) {
	data, err := readSecretFile(path)
	if err != nil {
		return nil, err
	}
	rawText := strings.TrimSpace(string(data))
	var raw []byte
	for _, decode := range []func(string) ([]byte, error){hex.DecodeString, base64.RawStdEncoding.DecodeString, base64.StdEncoding.DecodeString} {
		decoded, decodeErr := decode(rawText)
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
