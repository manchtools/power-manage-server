package main

import (
	"strings"
	"testing"
)

const validJWTSecret = "0123456789abcdef0123456789abcdef" // 32 chars

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
