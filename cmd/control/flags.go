// Flag + env-var parsing for the control server. Extracted from
// main.go (audit F043 / #157, slice 5) so the boot orchestration in
// main() reads as a sequence of subsystem builders rather than 100
// LOC of imperative flag wiring at the top.
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/manchtools/power-manage/server/internal/config"
)

// parseFlags wires the operator-facing flag set, applies env-var
// overrides, clamps the duration knobs to safe bounds, and aborts
// with a fatal log line on bad CONTROL_JWT_SECRET / TLS shape. The
// fatal-bail surface stays the same as the pre-extract main(): the
// validator either returns a Config or os.Exit(1)s on bad input.
func parseFlags() *Config {
	cfg := &Config{}

	flag.StringVar(&cfg.ListenAddr, "listen", ":8081", "Listen address")
	flag.StringVar(&cfg.DatabaseURL, "database-url", "", "PostgreSQL connection URL")
	flag.StringVar(&cfg.JWTSecret, "jwt-secret", "", "JWT secret key")
	flag.StringVar(&cfg.CACertPath, "ca-cert", "/certs/ca.crt", "CA certificate path")
	flag.StringVar(&cfg.CAKeyPath, "ca-key", "/certs/ca.key", "CA private key path")
	flag.DurationVar(&cfg.CertValidity, "cert-validity", 8760*time.Hour, "Certificate validity duration")
	flag.StringVar(&cfg.LogLevel, "log-level", "info", "Log level (debug, info, warn, error)")
	flag.StringVar(&cfg.LogFormat, "log-format", "text", "Log format (text, json)")
	flag.StringVar(&cfg.AdminEmail, "admin-email", "", "Initial admin user email")
	flag.StringVar(&cfg.AdminPassword, "admin-password", "", "Initial admin user password")
	flag.StringVar(&cfg.GatewayURL, "gateway-url", "", "Gateway URL returned to agents during registration")
	flag.StringVar(&cfg.TerminalGatewayURL, "terminal-gateway-url", "", "Public WebSocket URL of the gateway terminal endpoint (e.g. wss://gw.example.com/terminal). When empty, ControlService.StartTerminal returns CodeUnavailable.")
	flag.DurationVar(&cfg.DynamicGroupEvalInterval, "dynamic-group-eval-interval", time.Hour, "Interval for evaluating dynamic groups (min 30m, max 8h, 0 to disable)")
	// rc11 #77 — system-action reconciliation defaults: 1m interval keeps drift bounded for an
	// operator-visible UX path (role grant → terminal works), 5m sweep timeout is plenty for
	// even a 10k-user fleet because the sync is read-heavy and short-circuits on no-op users.
	flag.DurationVar(&cfg.SystemActionReconcileInterval, "system-action-reconcile-interval", time.Minute, "Period between full SyncAllUsersSystemActions sweeps; 0 disables periodic reconciliation")
	flag.DurationVar(&cfg.SystemActionReconcileTimeout, "system-action-reconcile-timeout", 5*time.Minute, "Per-sweep context deadline for the periodic reconciler")
	flag.StringVar(&cfg.CATrustBundlePath, "ca-trust-bundle", "", "PEM file with trusted CA certificates for verification (supports CA rotation)")
	flag.BoolVar(&cfg.TLSEnabled, "tls", false, "Enable TLS on public listener")
	flag.StringVar(&cfg.TLSCert, "tls-cert", "", "TLS certificate for public listener")
	flag.StringVar(&cfg.TLSKey, "tls-key", "", "TLS private key for public listener")
	flag.StringVar(&cfg.InternalListenAddr, "internal-listen", ":8082", "Internal mTLS listen address for gateway communication")
	flag.StringVar(&cfg.InternalTLSCert, "internal-tls-cert", "/certs/control.crt", "TLS certificate for internal mTLS listener")
	flag.StringVar(&cfg.InternalTLSKey, "internal-tls-key", "/certs/control.key", "TLS private key for internal mTLS listener")

	flag.Parse()

	applyEnvOverrides(cfg)
	clampDurations(cfg)
	mustValidateConfig(cfg)
	return cfg
}

// applyEnvOverrides applies CONTROL_* env-var overrides on top of
// the flag-parsed defaults. SSO_CALLBACK_BASE_URL inherits the first
// CORS origin when unset — a convenience for single-frontend deployments
// that almost always want them aligned.
func applyEnvOverrides(cfg *Config) {
	config.EnvString(&cfg.ListenAddr, "CONTROL_LISTEN_ADDR")
	config.EnvString(&cfg.DatabaseURL, "CONTROL_DATABASE_URL")
	config.EnvString(&cfg.JWTSecret, "CONTROL_JWT_SECRET")
	config.EnvString(&cfg.CACertPath, "CONTROL_CA_CERT")
	config.EnvString(&cfg.CAKeyPath, "CONTROL_CA_KEY")
	config.EnvString(&cfg.CATrustBundlePath, "CONTROL_CA_TRUST_BUNDLE")
	config.EnvBool(&cfg.TLSEnabled, "CONTROL_TLS_ENABLED", []string{"true", "1"}, []string{"false", "0"})
	config.EnvString(&cfg.TLSCert, "CONTROL_TLS_CERT")
	config.EnvString(&cfg.TLSKey, "CONTROL_TLS_KEY")
	config.EnvString(&cfg.InternalListenAddr, "CONTROL_INTERNAL_LISTEN_ADDR")
	config.EnvString(&cfg.InternalTLSCert, "CONTROL_INTERNAL_TLS_CERT")
	config.EnvString(&cfg.InternalTLSKey, "CONTROL_INTERNAL_TLS_KEY")
	config.EnvString(&cfg.AdminEmail, "CONTROL_ADMIN_EMAIL")
	config.EnvString(&cfg.AdminPassword, "CONTROL_ADMIN_PASSWORD")
	config.EnvString(&cfg.LogLevel, "CONTROL_LOG_LEVEL")
	config.EnvString(&cfg.LogFormat, "CONTROL_LOG_FORMAT")
	config.EnvString(&cfg.GatewayURL, "CONTROL_GATEWAY_URL")
	config.EnvString(&cfg.TerminalGatewayURL, "CONTROL_TERMINAL_GATEWAY_URL")
	config.EnvCSV(&cfg.CORSOrigins, "CONTROL_CORS_ORIGINS")
	config.EnvDuration(&cfg.DynamicGroupEvalInterval, "CONTROL_DYNAMIC_GROUP_EVAL_INTERVAL")
	config.EnvDuration(&cfg.SystemActionReconcileInterval, "CONTROL_SYSTEM_ACTION_RECONCILE_INTERVAL")
	config.EnvDuration(&cfg.SystemActionReconcileTimeout, "CONTROL_SYSTEM_ACTION_RECONCILE_TIMEOUT")

	cfg.PasswordAuthEnabled = true // default enabled
	config.EnvBool(&cfg.PasswordAuthEnabled, "CONTROL_PASSWORD_AUTH_ENABLED", []string{"true", "1"}, []string{"false", "0"})
	config.EnvString(&cfg.SSOCallbackBaseURL, "CONTROL_SSO_CALLBACK_BASE_URL")
	if cfg.SSOCallbackBaseURL == "" && len(cfg.CORSOrigins) > 0 {
		cfg.SSOCallbackBaseURL = cfg.CORSOrigins[0]
	}
	config.EnvString(&cfg.SCIMBaseURL, "CONTROL_SCIM_BASE_URL")
	config.EnvCSV(&cfg.TrustedProxies, "CONTROL_TRUSTED_PROXIES")
	config.EnvBool(&cfg.CORSAllowAll, "CONTROL_CORS_ALLOW_ALL", []string{"true", "1"}, []string{"false", "0"})

	config.EnvString(&cfg.ValkeyAddr, "CONTROL_VALKEY_ADDR")
	config.EnvString(&cfg.ValkeyPassword, "CONTROL_VALKEY_PASSWORD")
	config.EnvInt(&cfg.ValkeyDB, "CONTROL_VALKEY_DB")
}

// clampDurations enforces safe bounds on the duration knobs.
// DynamicGroupEvalInterval allows 0 (disabled).
// SystemActionReconcileTimeout's 0 case would silently break the
// durability safety net via context.WithTimeout returning an
// already-cancelled context, so it falls back to the 5min default
// rather than disabling.
func clampDurations(cfg *Config) {
	config.ClampInterval(&cfg.DynamicGroupEvalInterval, 30*time.Minute, 8*time.Hour)
	config.ClampInterval(&cfg.SystemActionReconcileInterval, 10*time.Second, 8*time.Hour)
	config.ClampDurationFloor(&cfg.SystemActionReconcileTimeout, 5*time.Minute, 0)
}

// mustValidateConfig enforces the boot-time invariants that turn a
// successful boot into a usable server. Logs a FATAL line and exits
// rather than returning err, matching the pre-extract main() shape.
func mustValidateConfig(cfg *Config) {
	if cfg.JWTSecret == "" {
		fmt.Fprintln(os.Stderr, "FATAL: CONTROL_JWT_SECRET (or -jwt-secret) is required")
		os.Exit(1)
	}
	if len(cfg.JWTSecret) < 32 {
		fmt.Fprintln(os.Stderr, "FATAL: CONTROL_JWT_SECRET must be at least 32 characters")
		os.Exit(1)
	}
	if cfg.TLSEnabled && (cfg.TLSCert == "" || cfg.TLSKey == "") {
		fmt.Fprintln(os.Stderr, "FATAL: -tls-cert and -tls-key are required when TLS is enabled")
		os.Exit(1)
	}
}
