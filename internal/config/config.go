// Package config provides configuration for the gateway server.
package config

import (
	"os"
	"strconv"
	"time"
)

// Heartbeat interval bounds. Agents must heartbeat at least once every
// 5 minutes so server-side liveness detection stays responsive, and no
// more often than every 5 seconds so we don't hammer the stream with
// keepalives that serve no purpose.
const (
	MinHeartbeatInterval     = 5 * time.Second
	MaxHeartbeatInterval     = 5 * time.Minute
	DefaultHeartbeatInterval = 30 * time.Second
)

// Config holds the gateway server configuration.
type Config struct {
	// Server settings
	ListenAddr string

	// Valkey settings
	ValkeyAddr     string
	ValkeyPassword string
	ValkeyDB       int

	// Control server URL for internal RPC proxying
	ControlURL string

	// Multi-gateway routing settings (used by the registry).
	//
	// GatewayID is the stable ID this gateway uses to register
	// itself in Valkey. Empty means "generate a fresh ULID at
	// startup" — appropriate for dynamic-config Traefik setups
	// (file provider with watcher, k8s headless service, etc.).
	// Set explicitly when running with a static-config Traefik
	// setup that pre-declares per-gateway routes.
	GatewayID string

	// PublicTerminalURLTemplate is the template the gateway uses
	// to compute its public WebSocket URL for terminal sessions.
	// '{id}' is substituted with GatewayID. Empty disables terminal
	// session registration on this gateway (the gateway still
	// accepts agent connections normally).
	//
	// Example: "wss://{id}.terminal.example.com/terminal"
	PublicTerminalURLTemplate string

	// PublicAgentURLTemplate is the template the gateway uses for
	// agent mTLS bootstrap redirects. '{id}' is substituted with
	// GatewayID. When an agent connects to BootstrapHost, the
	// gateway redirects to this URL so subsequent reconnects go
	// directly to this gateway instance. Empty means the redirect
	// hostname is derived from PublicTerminalURLTemplate (legacy
	// single-hostname mode — only valid when agent mTLS and
	// terminal traffic can share a hostname).
	//
	// Example: "https://{id}.gw.example.com"
	PublicAgentURLTemplate string

	// BootstrapHost is the wildcard root hostname agents use for
	// the initial connection before they have an assigned gateway.
	// When the gateway sees a request with this Host header, it
	// returns HTTP 307 with its own per-gateway URL so the client
	// can reconnect directly. Empty disables the bootstrap
	// redirect (single-gateway deployments don't need it).
	//
	// Example: "gateway.example.com"
	BootstrapHost string

	// Web listener for non-mTLS traffic (terminal WebSocket). This
	// listener serves cleartext HTTP on the private network; public TLS
	// terminates at Traefik before proxying to it. Empty disables the
	// web listener — terminal sessions won't work but agent connections
	// are unaffected.
	WebListenAddr string

	// InternalURL is the mTLS URL the control server uses to call
	// GatewayService RPCs on this gateway for admin fan-out. Published
	// to the registry so the control server can discover all gateways.
	// Example: "https://gw-01.internal:8080"
	InternalURL string

	// Traefik self-registration (via Redis KV provider).
	//
	// When TraefikSelfRegister is true, the gateway publishes its own
	// routing entries into the Traefik KV tree in Valkey, so scaling
	// the gateway deployment (`docker compose up --scale gateway=N`,
	// or adding replicas in k8s) works with zero operator touch per
	// instance. Operators enable this by also pointing Traefik at the
	// same Valkey instance via `--providers.redis`.
	//
	// All Traefik* fields below are required when TraefikSelfRegister
	// is true; the gateway will refuse to start otherwise.
	TraefikSelfRegister bool

	// TraefikRootKey matches Traefik's `--providers.redis.rootkey`
	// value. Defaults to "traefik" when empty.
	TraefikRootKey string

	// TraefikMTLSHost is the public HostSNI the shared TCP (passthrough)
	// router matches for agent mTLS. Example: "gateway.example.com".
	TraefikMTLSHost string

	// TraefikMTLSBackend is this replica's internal agent-mTLS
	// host:port reachable from Traefik. Example:
	// "gateway-1.internal:8080".
	TraefikMTLSBackend string

	// TraefikMTLSEntryPoint is the Traefik static-config entrypoint
	// the mTLS TCP router attaches to. Example: "mtls".
	TraefikMTLSEntryPoint string

	// TraefikTTYHost is the public Host header the per-replica HTTP
	// router matches for TTY WebSocket traffic. Example:
	// "tty.example.com". Each gateway gets path prefix /gw/<id>.
	TraefikTTYHost string

	// TraefikTTYBackend is this replica's internal TTY listener URL.
	// Cleartext is fine — Traefik terminates the public TLS.
	// Example: "http://gateway-1.internal:8443".
	TraefikTTYBackend string

	// TraefikTTYEntryPoint is the Traefik entrypoint the TTY HTTP
	// router attaches to. Example: "websecure".
	TraefikTTYEntryPoint string

	// TraefikTTYCertResolver is the Traefik certificate-resolver name
	// the TTY HTTP router uses to obtain a TLS cert (typically
	// "letsencrypt" matching --certificatesresolvers.letsencrypt.* on
	// Traefik's static config). Empty leaves the router with just
	// `tls = true`, which makes Traefik serve its default self-signed
	// cert — browser WebSocket clients refuse that, so unset is only
	// useful for bring-your-own-cert deployments that ship a
	// pre-matched default certificate for the TTY host.
	TraefikTTYCertResolver string

	// HeartbeatInterval is the default heartbeat cadence sent to every
	// agent in the Welcome message. Clamped to [MinHeartbeatInterval,
	// MaxHeartbeatInterval] in FromEnv.
	HeartbeatInterval time.Duration

	// Logging
	LogLevel string
}

// FromEnv loads configuration from environment variables.
//
// rc3 note: the gateway previously read VALKEY_ADDR / VALKEY_PASSWORD /
// VALKEY_DB / LOG_LEVEL unprefixed. Those are now GATEWAY_VALKEY_ADDR
// / GATEWAY_VALKEY_PASSWORD / GATEWAY_VALKEY_DB / GATEWAY_LOG_LEVEL so
// every gateway knob shares one namespace and nothing silently aliases
// a global the way the old names could. The old names no longer work;
// operators upgrading from rc2 must rename their .env entries.
func FromEnv() *Config {
	// Traefik self-registration defaults: the previous shape forced
	// operators to set seven GATEWAY_TRAEFIK_* env vars by hand, and
	// every real deployment set them to the same values. The defaults
	// here match the reference compose:
	//
	//   * SelfRegister = true   — scaling-ready out of the box
	//   * RootKey      = traefik — matches Traefik default --providers.redis.rootkey
	//   * MTLSHost     = GATEWAY_DOMAIN   (not Traefik-prefixed — one name per thing)
	//   * MTLSEntryPoint    = websecure   (same :443 as control, SNI-separated)
	//   * TTYHost      = GATEWAY_TTY_DOMAIN (falls back to empty -> TTY router disabled)
	//   * TTYEntryPoint     = websecure
	//   * TTYCertResolver   = letsencrypt
	//
	// Backends (MTLSBackend / TTYBackend) are auto-derived from the
	// gateway's own routable IP address in cmd/gateway/main.go, so
	// operators normally never set them either. Explicit values
	// override the defaults in each case — useful for bring-your-own-
	// Traefik topologies that differ from the reference stack.
	return &Config{
		ListenAddr:                getEnv("GATEWAY_LISTEN_ADDR", ":8080"),
		ValkeyAddr:                getEnv("GATEWAY_VALKEY_ADDR", "localhost:6379"),
		ValkeyPassword:            getEnv("GATEWAY_VALKEY_PASSWORD", ""),
		ValkeyDB:                  getEnvInt("GATEWAY_VALKEY_DB", 0),
		ControlURL:                getEnv("GATEWAY_CONTROL_URL", "https://control:8082"),
		GatewayID:                 getEnv("GATEWAY_ID", ""),
		PublicTerminalURLTemplate: getEnv("GATEWAY_PUBLIC_TERMINAL_URL_TEMPLATE", ""),
		PublicAgentURLTemplate:    getEnv("GATEWAY_PUBLIC_AGENT_URL_TEMPLATE", ""),
		BootstrapHost:             getEnv("GATEWAY_BOOTSTRAP_HOST", ""),
		WebListenAddr:             getEnv("GATEWAY_WEB_LISTEN_ADDR", ""),
		InternalURL:               getEnv("GATEWAY_INTERNAL_URL", ""),
		TraefikSelfRegister:       getEnvBool("GATEWAY_TRAEFIK_SELF_REGISTER", true),
		TraefikRootKey:            getEnv("GATEWAY_TRAEFIK_ROOT_KEY", "traefik"),
		// MTLSHost reads GATEWAY_DOMAIN directly — same env var the
		// rest of the stack uses, no separate GATEWAY_TRAEFIK_MTLS_HOST.
		TraefikMTLSHost:        firstNonEmpty(os.Getenv("GATEWAY_TRAEFIK_MTLS_HOST"), os.Getenv("GATEWAY_DOMAIN")),
		TraefikMTLSBackend:     getEnv("GATEWAY_TRAEFIK_MTLS_BACKEND", ""),
		TraefikMTLSEntryPoint:  getEnv("GATEWAY_TRAEFIK_MTLS_ENTRYPOINT", "websecure"),
		// TTYHost falls back through GATEWAY_TTY_DOMAIN (dedicated
		// TTY subdomain) to GATEWAY_DOMAIN (single-domain deploys
		// where terminal WebSocket shares the gateway hostname).
		// .env.example documents exactly this chain; rc9 only
		// implemented the first two rungs, which was the hidden
		// empty-host trap that crashed gateway startup in staging.
		TraefikTTYHost: firstNonEmpty(
			os.Getenv("GATEWAY_TRAEFIK_TTY_HOST"),
			os.Getenv("GATEWAY_TTY_DOMAIN"),
			os.Getenv("GATEWAY_DOMAIN"),
		),
		TraefikTTYBackend:      getEnv("GATEWAY_TRAEFIK_TTY_BACKEND", ""),
		TraefikTTYEntryPoint:   getEnv("GATEWAY_TRAEFIK_TTY_ENTRYPOINT", "websecure"),
		TraefikTTYCertResolver: getEnv("GATEWAY_TRAEFIK_TTY_CERT_RESOLVER", "letsencrypt"),
		HeartbeatInterval:      getEnvHeartbeatInterval("GATEWAY_HEARTBEAT_INTERVAL"),
		LogLevel:               getEnv("GATEWAY_LOG_LEVEL", "info"),
	}
}

// firstNonEmpty returns the first argument that isn't the empty
// string. Used to resolve an env-var name (the legacy one) with a
// more-preferred name as the primary source.
func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// getEnvHeartbeatInterval parses GATEWAY_HEARTBEAT_INTERVAL (a Go
// duration string) and clamps it to [MinHeartbeatInterval,
// MaxHeartbeatInterval]. An unset, empty, or unparseable value falls
// back to DefaultHeartbeatInterval so the gateway always comes up with
// a sensible cadence.
func getEnvHeartbeatInterval(key string) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return DefaultHeartbeatInterval
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return DefaultHeartbeatInterval
	}
	if d < MinHeartbeatInterval {
		return MinHeartbeatInterval
	}
	if d > MaxHeartbeatInterval {
		return MaxHeartbeatInterval
	}
	return d
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if i, err := strconv.Atoi(value); err == nil {
			return i
		}
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if b, err := strconv.ParseBool(value); err == nil {
			return b
		}
	}
	return defaultValue
}
