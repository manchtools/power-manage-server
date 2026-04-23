package config

import (
	"testing"
)

func TestFromEnv_Defaults(t *testing.T) {
	// Clear any env vars that might be set. rc3 renamed the unprefixed
	// VALKEY_* / LOG_LEVEL knobs into the GATEWAY_* namespace so every
	// gateway config variable shares one prefix.
	for _, key := range []string{
		"GATEWAY_LISTEN_ADDR", "GATEWAY_VALKEY_ADDR", "GATEWAY_VALKEY_PASSWORD",
		"GATEWAY_VALKEY_DB", "GATEWAY_CONTROL_URL", "GATEWAY_LOG_LEVEL",
	} {
		t.Setenv(key, "")
	}

	cfg := FromEnv()

	if cfg.ListenAddr != ":8080" {
		t.Errorf("ListenAddr = %q, want %q", cfg.ListenAddr, ":8080")
	}
	if cfg.ValkeyAddr != "localhost:6379" {
		t.Errorf("ValkeyAddr = %q, want %q", cfg.ValkeyAddr, "localhost:6379")
	}
	if cfg.ValkeyPassword != "" {
		t.Errorf("ValkeyPassword = %q, want empty", cfg.ValkeyPassword)
	}
	if cfg.ValkeyDB != 0 {
		t.Errorf("ValkeyDB = %d, want 0", cfg.ValkeyDB)
	}
	if cfg.ControlURL != "https://control:8082" {
		t.Errorf("ControlURL = %q, want %q", cfg.ControlURL, "https://control:8082")
	}
	if cfg.LogLevel != "info" {
		t.Errorf("LogLevel = %q, want %q", cfg.LogLevel, "info")
	}
}

func TestFromEnv_CustomValues(t *testing.T) {
	t.Setenv("GATEWAY_LISTEN_ADDR", ":9090")
	t.Setenv("GATEWAY_VALKEY_ADDR", "valkey:6380")
	t.Setenv("GATEWAY_VALKEY_PASSWORD", "secret")
	t.Setenv("GATEWAY_VALKEY_DB", "3")
	t.Setenv("GATEWAY_CONTROL_URL", "https://localhost:8082")
	t.Setenv("GATEWAY_LOG_LEVEL", "debug")

	cfg := FromEnv()

	if cfg.ListenAddr != ":9090" {
		t.Errorf("ListenAddr = %q, want %q", cfg.ListenAddr, ":9090")
	}
	if cfg.ValkeyAddr != "valkey:6380" {
		t.Errorf("ValkeyAddr = %q, want %q", cfg.ValkeyAddr, "valkey:6380")
	}
	if cfg.ValkeyPassword != "secret" {
		t.Errorf("ValkeyPassword = %q, want %q", cfg.ValkeyPassword, "secret")
	}
	if cfg.ValkeyDB != 3 {
		t.Errorf("ValkeyDB = %d, want 3", cfg.ValkeyDB)
	}
	if cfg.ControlURL != "https://localhost:8082" {
		t.Errorf("ControlURL = %q, want %q", cfg.ControlURL, "https://localhost:8082")
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("LogLevel = %q, want %q", cfg.LogLevel, "debug")
	}
}

func TestFromEnv_InvalidValkeyDB_UsesDefault(t *testing.T) {
	t.Setenv("GATEWAY_VALKEY_DB", "not-a-number")

	cfg := FromEnv()

	if cfg.ValkeyDB != 0 {
		t.Errorf("ValkeyDB = %d, want 0 (default on invalid input)", cfg.ValkeyDB)
	}
}

// rc3: unprefixed VALKEY_* / LOG_LEVEL must not be read. Anyone upgrading
// from rc2 who forgets to rename their env gets default values, not a
// silent half-configured gateway.
func TestFromEnv_IgnoresOldUnprefixedVars(t *testing.T) {
	t.Setenv("VALKEY_ADDR", "old:6379")
	t.Setenv("VALKEY_PASSWORD", "old-secret")
	t.Setenv("VALKEY_DB", "9")
	t.Setenv("LOG_LEVEL", "debug")
	// Ensure nothing leaks in from the rc3 vars either.
	t.Setenv("GATEWAY_VALKEY_ADDR", "")
	t.Setenv("GATEWAY_VALKEY_PASSWORD", "")
	t.Setenv("GATEWAY_VALKEY_DB", "")
	t.Setenv("GATEWAY_LOG_LEVEL", "")

	cfg := FromEnv()

	if cfg.ValkeyAddr != "localhost:6379" {
		t.Errorf("ValkeyAddr = %q, want default (unprefixed VALKEY_ADDR must not be read)", cfg.ValkeyAddr)
	}
	if cfg.ValkeyPassword != "" {
		t.Errorf("ValkeyPassword = %q, want empty (unprefixed VALKEY_PASSWORD must not be read)", cfg.ValkeyPassword)
	}
	if cfg.ValkeyDB != 0 {
		t.Errorf("ValkeyDB = %d, want 0 (unprefixed VALKEY_DB must not be read)", cfg.ValkeyDB)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("LogLevel = %q, want default (unprefixed LOG_LEVEL must not be read)", cfg.LogLevel)
	}
}

func TestFromEnv_TraefikTTYCertResolver(t *testing.T) {
	t.Setenv("GATEWAY_TRAEFIK_TTY_CERT_RESOLVER", "custom-resolver")
	cfg := FromEnv()
	if cfg.TraefikTTYCertResolver != "custom-resolver" {
		t.Errorf("TraefikTTYCertResolver = %q, want %q", cfg.TraefikTTYCertResolver, "custom-resolver")
	}

	t.Setenv("GATEWAY_TRAEFIK_TTY_CERT_RESOLVER", "")
	cfg = FromEnv()
	if cfg.TraefikTTYCertResolver != "letsencrypt" {
		t.Errorf("TraefikTTYCertResolver = %q, want %q (default)", cfg.TraefikTTYCertResolver, "letsencrypt")
	}
}

// TestValidate_TTYMTLSHostCollision captures the config-shape invariant
// CodeRabbit flagged on the rc10 review: when the terminal WebSocket
// listener is enabled AND Traefik self-registration is on, the TTY
// host must not equal the mTLS host. If they match, Traefik's TCP
// passthrough router for the shared SNI wins over the TTY HTTP router
// and the WebSocket handshake fails against the mTLS backend.
func TestValidate_TTYMTLSHostCollision(t *testing.T) {
	cases := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name: "collision with terminal enabled (WebListenAddr) → error",
			cfg: Config{
				TraefikSelfRegister:   true,
				WebListenAddr:         ":8443",
				TraefikMTLSHost:       "gw.example.com",
				TraefikTTYHost:        "gw.example.com",
				TraefikMTLSEntryPoint: "websecure",
				TraefikTTYEntryPoint:  "websecure",
			},
			wantErr: true,
		},
		{
			name: "collision with terminal enabled (explicit TTYBackend) → error",
			cfg: Config{
				TraefikSelfRegister:   true,
				TraefikTTYBackend:     "http://10.0.0.5:8443",
				TraefikMTLSHost:       "gw.example.com",
				TraefikTTYHost:        "gw.example.com",
				TraefikMTLSEntryPoint: "websecure",
				TraefikTTYEntryPoint:  "websecure",
			},
			wantErr: true,
		},
		{
			name: "collision but terminal disabled → OK",
			cfg: Config{
				TraefikSelfRegister:   true,
				WebListenAddr:         "", // terminal off
				TraefikTTYBackend:     "",
				TraefikMTLSHost:       "gw.example.com",
				TraefikTTYHost:        "gw.example.com",
				TraefikMTLSEntryPoint: "websecure",
				TraefikTTYEntryPoint:  "websecure",
			},
			wantErr: false,
		},
		{
			name: "distinct hosts with terminal enabled → OK",
			cfg: Config{
				TraefikSelfRegister:   true,
				WebListenAddr:         ":8443",
				TraefikMTLSHost:       "gw.example.com",
				TraefikTTYHost:        "tty.example.com",
				TraefikMTLSEntryPoint: "websecure",
				TraefikTTYEntryPoint:  "websecure",
			},
			wantErr: false,
		},
		{
			name: "shared host but different entrypoints → OK (routers don't collide)",
			cfg: Config{
				TraefikSelfRegister:   true,
				WebListenAddr:         ":8443",
				TraefikMTLSHost:       "gw.example.com",
				TraefikTTYHost:        "gw.example.com",
				TraefikMTLSEntryPoint: "mtls",
				TraefikTTYEntryPoint:  "websecure",
			},
			wantErr: false,
		},
		{
			name: "collision but self-register off → OK (operator owns routing)",
			cfg: Config{
				TraefikSelfRegister:   false,
				WebListenAddr:         ":8443",
				TraefikMTLSHost:       "gw.example.com",
				TraefikTTYHost:        "gw.example.com",
				TraefikMTLSEntryPoint: "websecure",
				TraefikTTYEntryPoint:  "websecure",
			},
			wantErr: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if tc.wantErr && err == nil {
				t.Fatalf("Validate() = nil, want error for %+v", tc.cfg)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("Validate() = %v, want nil for %+v", err, tc.cfg)
			}
		})
	}
}

func TestGetEnvInt_ValidValues(t *testing.T) {
	tests := []struct {
		name     string
		envVal   string
		fallback int
		want     int
	}{
		{"positive", "42", 0, 42},
		{"zero", "0", 5, 0},
		{"negative", "-1", 0, -1},
		{"empty uses default", "", 7, 7},
		{"invalid uses default", "abc", 7, 7},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("TEST_INT_VAR", tt.envVal)
			got := getEnvInt("TEST_INT_VAR", tt.fallback)
			if got != tt.want {
				t.Errorf("getEnvInt() = %d, want %d", got, tt.want)
			}
		})
	}
}
