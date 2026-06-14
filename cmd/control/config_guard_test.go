package main

import (
	"strings"
	"testing"
)

// validJWTSecret is 64 hex chars = 32 decoded bytes, the entropy floor
// CONTROL_JWT_SECRET now requires (WS11 finding 4).
const validJWTSecret = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

// TestValidateConfig_RefusesAllowAllInProd pins WS5 #7: CORS allow-all is
// dev-only — validateConfig must refuse to boot it when TLS is enabled or the
// listen address is not localhost, and must accept it for localhost dev.
func TestValidateConfig_RefusesAllowAllInProd(t *testing.T) {
	cases := []struct {
		name       string
		listenAddr string
		tlsEnabled bool
		allowAll   bool
		wantErr    bool
	}{
		{"allow_all_localhost_ok", "127.0.0.1:8081", false, true, false},
		{"allow_all_localhost_named_ok", "localhost:8081", false, true, false},
		{"allow_all_ipv6_loopback_ok", "[::1]:8081", false, true, false},
		{"allow_all_bind_all_refused", ":8081", false, true, true},
		{"allow_all_zero_addr_refused", "0.0.0.0:8081", false, true, true},
		{"allow_all_public_addr_refused", "10.0.0.5:8081", false, true, true},
		{"allow_all_with_tls_refused", "127.0.0.1:8081", true, true, true},
		{"no_allow_all_public_ok", "0.0.0.0:8081", false, false, false},
		{"no_allow_all_tls_ok", "127.0.0.1:8081", true, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{
				JWTSecret:    validJWTSecret,
				ListenAddr:   tc.listenAddr,
				TLSEnabled:   tc.tlsEnabled,
				CORSAllowAll: tc.allowAll,
			}
			if tc.tlsEnabled {
				cfg.TLSCert, cfg.TLSKey = "cert.pem", "key.pem"
			}
			err := validateConfig(cfg)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected validateConfig to refuse %s (allowAll=%v tls=%v addr=%q)", tc.name, tc.allowAll, tc.tlsEnabled, tc.listenAddr)
				}
				if !strings.Contains(err.Error(), "CORS_ALLOW_ALL") {
					t.Fatalf("error should name the offending flag, got: %v", err)
				}
			} else if err != nil {
				t.Fatalf("validateConfig should accept %s, got: %v", tc.name, err)
			}
		})
	}
}

// TestValidateConfig_JWTSecret pins the existing JWT invariants still hold via
// the extracted pure validator.
func TestValidateConfig_JWTSecret(t *testing.T) {
	if err := validateConfig(&Config{JWTSecret: "", ListenAddr: "127.0.0.1:8081"}); err == nil {
		t.Fatal("missing JWT secret must error")
	}
	if err := validateConfig(&Config{JWTSecret: "too-short", ListenAddr: "127.0.0.1:8081"}); err == nil {
		t.Fatal("short JWT secret must error")
	}
	if err := validateConfig(&Config{JWTSecret: validJWTSecret, ListenAddr: "127.0.0.1:8081"}); err != nil {
		t.Fatalf("valid minimal config should pass: %v", err)
	}
}

// TestValidateConfig_JWTSecretEntropyFloor pins WS11 finding 4: the secret must
// decode (hex or base64) to >= 32 random bytes, not merely be >= 32 characters.
// "wrong" is sourced from the intent ("32 RANDOM bytes"), not the old length
// rule — so a 32-char value that passed before is now rejected.
func TestValidateConfig_JWTSecretEntropyFloor(t *testing.T) {
	cases := []struct {
		name    string
		secret  string
		wantErr bool
	}{
		{"absent", "", true},
		{"32 hex chars decode to only 16 bytes (passed the old rule)", "0123456789abcdef0123456789abcdef", true},
		{"40-char low-entropy all-a decodes under 32 bytes", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", true},
		{"non-encoded 32-char passphrase is rejected", "this is a passphrase not base64!", true},
		{"64 hex chars = 32 bytes", validJWTSecret, false},
		{"44-char base64 = 33 bytes", "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8g", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateConfig(&Config{JWTSecret: tc.secret, ListenAddr: "127.0.0.1:8081"})
			if tc.wantErr && err == nil {
				t.Fatalf("expected %q to be rejected by the entropy floor", tc.secret)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected %q to pass the entropy floor, got: %v", tc.secret, err)
			}
		})
	}
}

// TestValidateConfig_AdminPasswordFloor pins WS11 finding 9: a bootstrap admin
// password must clear a minimum-length floor (the documented "admin" example is
// rejected). An admin email with NO password is the no-bootstrap path (allowed)
// so an operator can drop the password from the env after first boot without
// the server refusing to start.
func TestValidateConfig_AdminPasswordFloor(t *testing.T) {
	base := func(email, pw string) *Config {
		return &Config{JWTSecret: validJWTSecret, ListenAddr: "127.0.0.1:8081", AdminEmail: email, AdminPassword: pw}
	}
	cases := []struct {
		name    string
		cfg     *Config
		wantErr bool
	}{
		{"weak admin example rejected", base("admin@example.com", "admin"), true},
		{"empty password with email set is the no-bootstrap path", base("admin@example.com", ""), false},
		{"strong password accepted", base("admin@example.com", "a-strong-bootstrap-secret"), false},
		{"no admin configured at all", base("", ""), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateConfig(tc.cfg)
			if tc.wantErr && err == nil {
				t.Fatal("expected the admin-password floor to reject this config")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected this config to pass, got: %v", err)
			}
		})
	}
}
