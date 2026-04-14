// Package config provides configuration for the gateway server.
package config

import (
	"os"
	"strconv"
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
	// Example: "wss://{id}.gateway.example.com/terminal"
	PublicTerminalURLTemplate string

	// BootstrapHost is the wildcard root hostname agents use for
	// the initial connection before they have an assigned gateway.
	// When the gateway sees a request with this Host header, it
	// returns HTTP 307 with its own per-gateway URL so the client
	// can reconnect directly. Empty disables the bootstrap
	// redirect (single-gateway deployments don't need it).
	//
	// Example: "gateway.example.com"
	BootstrapHost string

	// Web listener for non-mTLS traffic (terminal WebSocket). Uses
	// standard TLS (server cert only, no client cert) so web browsers
	// can connect. Empty disables the web listener — terminal
	// sessions won't work but agent connections are unaffected.
	WebListenAddr string

	// InternalURL is the mTLS URL the control server uses to call
	// GatewayService RPCs on this gateway for admin fan-out. Published
	// to the registry so the control server can discover all gateways.
	// Example: "https://gw-01.internal:8080"
	InternalURL string

	// Logging
	LogLevel string
}

// FromEnv loads configuration from environment variables.
func FromEnv() *Config {
	return &Config{
		ListenAddr:                getEnv("GATEWAY_LISTEN_ADDR", ":8080"),
		ValkeyAddr:                getEnv("VALKEY_ADDR", "localhost:6379"),
		ValkeyPassword:            getEnv("VALKEY_PASSWORD", ""),
		ValkeyDB:                  getEnvInt("VALKEY_DB", 0),
		ControlURL:                getEnv("GATEWAY_CONTROL_URL", "http://control:8081"),
		GatewayID:                 getEnv("GATEWAY_ID", ""),
		PublicTerminalURLTemplate: getEnv("GATEWAY_PUBLIC_TERMINAL_URL_TEMPLATE", ""),
		BootstrapHost:             getEnv("GATEWAY_BOOTSTRAP_HOST", ""),
		WebListenAddr:             getEnv("GATEWAY_WEB_LISTEN_ADDR", ""),
		InternalURL:               getEnv("GATEWAY_INTERNAL_URL", ""),
		LogLevel:                  getEnv("LOG_LEVEL", "info"),
	}
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
