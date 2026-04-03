package config

import (
	"testing"
)

func TestFromEnv_Defaults(t *testing.T) {
	// Clear any env vars that might be set
	for _, key := range []string{
		"GATEWAY_LISTEN_ADDR", "VALKEY_ADDR", "VALKEY_PASSWORD",
		"VALKEY_DB", "GATEWAY_CONTROL_URL", "LOG_LEVEL",
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
	if cfg.ControlURL != "http://control:8081" {
		t.Errorf("ControlURL = %q, want %q", cfg.ControlURL, "http://control:8081")
	}
	if cfg.LogLevel != "info" {
		t.Errorf("LogLevel = %q, want %q", cfg.LogLevel, "info")
	}
}

func TestFromEnv_CustomValues(t *testing.T) {
	t.Setenv("GATEWAY_LISTEN_ADDR", ":9090")
	t.Setenv("VALKEY_ADDR", "valkey:6380")
	t.Setenv("VALKEY_PASSWORD", "secret")
	t.Setenv("VALKEY_DB", "3")
	t.Setenv("GATEWAY_CONTROL_URL", "http://localhost:8081")
	t.Setenv("LOG_LEVEL", "debug")

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
	if cfg.ControlURL != "http://localhost:8081" {
		t.Errorf("ControlURL = %q, want %q", cfg.ControlURL, "http://localhost:8081")
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("LogLevel = %q, want %q", cfg.LogLevel, "debug")
	}
}

func TestFromEnv_InvalidValkeyDB_UsesDefault(t *testing.T) {
	t.Setenv("VALKEY_DB", "not-a-number")

	cfg := FromEnv()

	if cfg.ValkeyDB != 0 {
		t.Errorf("ValkeyDB = %d, want 0 (default on invalid input)", cfg.ValkeyDB)
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
