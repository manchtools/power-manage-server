package registry

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func baseTraefikConfig() TraefikRouteConfig {
	return TraefikRouteConfig{
		MTLSHost:       "gateway.example.com",
		MTLSBackend:    "gateway-1.internal:8443",
		MTLSEntryPoint: "mtls",
		TTYHost:        "tty.example.com",
		TTYBackend:     "http://gateway-1.internal:8080",
		TTYEntryPoint:  "websecure",
	}
}

func TestPublishTraefikRoute_WritesExpectedKeys(t *testing.T) {
	backend := NewFakeBackend(nil)
	r := New(backend, nil)
	ctx := context.Background()

	cfg := baseTraefikConfig()
	if err := r.PublishTraefikRoute(ctx, "gw-1", cfg, 30*time.Second); err != nil {
		t.Fatalf("publish: %v", err)
	}

	want := map[string]string{
		"traefik/tcp/routers/pm-mtls/rule":                               "HostSNI(`gateway.example.com`)",
		"traefik/tcp/routers/pm-mtls/entrypoints/0":                      "mtls",
		"traefik/tcp/routers/pm-mtls/tls/passthrough":                    "true",
		"traefik/tcp/routers/pm-mtls/service":                            "pm-mtls",
		"traefik/tcp/services/pm-mtls/loadbalancer/servers/gw-1/address": "gateway-1.internal:8443",
		"traefik/http/routers/pm-tty-gw-1/rule":                          "Host(`tty.example.com`) && PathPrefix(`/gw/gw-1`)",
		"traefik/http/routers/pm-tty-gw-1/entrypoints/0":                 "websecure",
		"traefik/http/routers/pm-tty-gw-1/tls":                           "true",
		"traefik/http/routers/pm-tty-gw-1/service":                       "pm-tty-gw-1",
		"traefik/http/services/pm-tty-gw-1/loadbalancer/servers/0/url":   "http://gateway-1.internal:8080",
	}

	for key, expected := range want {
		got, err := backend.Get(ctx, key)
		if err != nil {
			t.Errorf("missing key %q: %v", key, err)
			continue
		}
		if got != expected {
			t.Errorf("key %q: got %q, want %q", key, got, expected)
		}
	}

	// Without TTYCertResolver set, the BYO-cert path is active:
	// only the flat /tls = "true" is written, never any nested
	// /tls/* keys. Coexistence would break Traefik's KV parse.
	if _, err := backend.Get(ctx, "traefik/http/routers/pm-tty-gw-1/tls/certResolver"); !errors.Is(err, ErrNoGateway) {
		t.Errorf("tls/certResolver must not coexist with flat /tls; got err=%v", err)
	}
}

func TestPublishTraefikRoute_CertResolver_NestedOnly(t *testing.T) {
	backend := NewFakeBackend(nil)
	r := New(backend, nil)
	ctx := context.Background()

	cfg := baseTraefikConfig()
	cfg.TTYCertResolver = "letsencrypt"

	if err := r.PublishTraefikRoute(ctx, "gw-1", cfg, 30*time.Second); err != nil {
		t.Fatalf("publish: %v", err)
	}

	got, err := backend.Get(ctx, "traefik/http/routers/pm-tty-gw-1/tls/certResolver")
	if err != nil {
		t.Fatalf("tls/certResolver missing: %v", err)
	}
	if got != "letsencrypt" {
		t.Errorf("tls/certResolver got %q, want %q", got, "letsencrypt")
	}

	// Critical invariant: the flat /tls string MUST NOT coexist with
	// the nested certResolver key, because Traefik's KV walker treats
	// the flat scalar as a leaf that blocks the nested subtree — the
	// whole failure mode rc3 exists to fix.
	if _, err := backend.Get(ctx, "traefik/http/routers/pm-tty-gw-1/tls"); !errors.Is(err, ErrNoGateway) {
		t.Errorf("flat /tls key must not be written when TTYCertResolver is set; got err=%v", err)
	}
}

func TestRevokeTraefikRoute_CleansBothTLSShapes(t *testing.T) {
	backend := NewFakeBackend(nil)
	r := New(backend, nil)
	ctx := context.Background()

	// Seed both shapes directly — simulates a replica that flipped
	// between BYO-cert and certResolver across restarts, leaving one
	// stale key behind.
	ctxBg := context.Background()
	if err := backend.Set(ctxBg, "traefik/http/routers/pm-tty-gw-1/tls", "true", 30*time.Second); err != nil {
		t.Fatalf("seed flat /tls: %v", err)
	}
	if err := backend.Set(ctxBg, "traefik/http/routers/pm-tty-gw-1/tls/certResolver", "letsencrypt", 30*time.Second); err != nil {
		t.Fatalf("seed nested certResolver: %v", err)
	}

	cfg := baseTraefikConfig()
	cfg.TTYCertResolver = "letsencrypt"
	if err := r.PublishTraefikRoute(ctx, "gw-1", cfg, 30*time.Second); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if err := r.RevokeTraefikRoute(ctx, "gw-1", cfg); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	for _, key := range []string{
		"traefik/http/routers/pm-tty-gw-1/tls",
		"traefik/http/routers/pm-tty-gw-1/tls/certResolver",
	} {
		if _, err := backend.Get(ctx, key); !errors.Is(err, ErrNoGateway) {
			t.Errorf("key %q should be deleted after revoke, got err=%v", key, err)
		}
	}
}

func TestPublishTraefikRoute_CustomRootKey(t *testing.T) {
	backend := NewFakeBackend(nil)
	r := New(backend, nil)
	ctx := context.Background()

	cfg := baseTraefikConfig()
	cfg.RootKey = "pm-traefik"
	if err := r.PublishTraefikRoute(ctx, "gw-A", cfg, 30*time.Second); err != nil {
		t.Fatalf("publish: %v", err)
	}

	if _, err := backend.Get(ctx, "pm-traefik/tcp/routers/pm-mtls/rule"); err != nil {
		t.Errorf("expected custom rootkey keys to be written: %v", err)
	}
	if _, err := backend.Get(ctx, "traefik/tcp/routers/pm-mtls/rule"); !errors.Is(err, ErrNoGateway) {
		t.Errorf("default rootkey should not be used when RootKey is set; got err=%v", err)
	}
}

func TestPublishTraefikRoute_RejectsEmptyFields(t *testing.T) {
	r := New(NewFakeBackend(nil), nil)
	ctx := context.Background()

	bad := baseTraefikConfig()
	bad.MTLSHost = ""
	bad.TTYBackend = ""

	err := r.PublishTraefikRoute(ctx, "gw-1", bad, 30*time.Second)
	if err == nil {
		t.Fatal("expected validation error for empty MTLSHost and TTYBackend")
	}
	if !strings.Contains(err.Error(), "MTLSHost") || !strings.Contains(err.Error(), "TTYBackend") {
		t.Errorf("error should name all missing fields; got: %v", err)
	}
}

func TestPublishTraefikRoute_RejectsEmptyGatewayID(t *testing.T) {
	r := New(NewFakeBackend(nil), nil)
	if err := r.PublishTraefikRoute(context.Background(), "", baseTraefikConfig(), 30*time.Second); err == nil {
		t.Fatal("expected error for empty gatewayID")
	}
}

func TestPublishTraefikRoute_Idempotent(t *testing.T) {
	backend := NewFakeBackend(nil)
	r := New(backend, nil)
	ctx := context.Background()
	cfg := baseTraefikConfig()

	if err := r.PublishTraefikRoute(ctx, "gw-1", cfg, 30*time.Second); err != nil {
		t.Fatalf("first publish: %v", err)
	}
	if err := r.PublishTraefikRoute(ctx, "gw-1", cfg, 30*time.Second); err != nil {
		t.Errorf("second publish should be idempotent, got: %v", err)
	}
}

func TestRevokeTraefikRoute_DeletesPerReplicaOnly(t *testing.T) {
	backend := NewFakeBackend(nil)
	r := New(backend, nil)
	ctx := context.Background()
	cfg := baseTraefikConfig()

	if err := r.PublishTraefikRoute(ctx, "gw-1", cfg, 30*time.Second); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if err := r.RevokeTraefikRoute(ctx, "gw-1", cfg); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	// Per-replica keys must be gone.
	perReplicaGone := []string{
		"traefik/tcp/services/pm-mtls/loadbalancer/servers/gw-1/address",
		"traefik/http/routers/pm-tty-gw-1/rule",
		"traefik/http/services/pm-tty-gw-1/loadbalancer/servers/0/url",
	}
	for _, key := range perReplicaGone {
		if _, err := backend.Get(ctx, key); !errors.Is(err, ErrNoGateway) {
			t.Errorf("key %q should be deleted after revoke, got err=%v", key, err)
		}
	}

	// Shared keys must still be present — other replicas rely on them.
	sharedStays := []string{
		"traefik/tcp/routers/pm-mtls/rule",
		"traefik/tcp/routers/pm-mtls/service",
	}
	for _, key := range sharedStays {
		if _, err := backend.Get(ctx, key); err != nil {
			t.Errorf("shared key %q must NOT be deleted by revoke, got err=%v", key, err)
		}
	}
}

func TestRevokeTraefikRoute_Idempotent(t *testing.T) {
	r := New(NewFakeBackend(nil), nil)
	if err := r.RevokeTraefikRoute(context.Background(), "never-published", baseTraefikConfig()); err != nil {
		t.Errorf("revoke of unknown gateway should be idempotent, got %v", err)
	}
}

func TestPublishTraefikRoute_TwoReplicas_SharedService(t *testing.T) {
	backend := NewFakeBackend(nil)
	r := New(backend, nil)
	ctx := context.Background()

	cfgA := baseTraefikConfig()
	cfgA.MTLSBackend = "gateway-A.internal:8443"
	cfgA.TTYBackend = "http://gateway-A.internal:8080"

	cfgB := baseTraefikConfig()
	cfgB.MTLSBackend = "gateway-B.internal:8443"
	cfgB.TTYBackend = "http://gateway-B.internal:8080"

	if err := r.PublishTraefikRoute(ctx, "gw-A", cfgA, 30*time.Second); err != nil {
		t.Fatalf("publish A: %v", err)
	}
	if err := r.PublishTraefikRoute(ctx, "gw-B", cfgB, 30*time.Second); err != nil {
		t.Fatalf("publish B: %v", err)
	}

	addrA, err := backend.Get(ctx, "traefik/tcp/services/pm-mtls/loadbalancer/servers/gw-A/address")
	if err != nil || addrA != "gateway-A.internal:8443" {
		t.Errorf("replica A address got %q err=%v", addrA, err)
	}
	addrB, err := backend.Get(ctx, "traefik/tcp/services/pm-mtls/loadbalancer/servers/gw-B/address")
	if err != nil || addrB != "gateway-B.internal:8443" {
		t.Errorf("replica B address got %q err=%v", addrB, err)
	}

	// Shared rule must be present once (same value from both writes).
	rule, err := backend.Get(ctx, "traefik/tcp/routers/pm-mtls/rule")
	if err != nil {
		t.Fatalf("shared rule: %v", err)
	}
	if rule != "HostSNI(`gateway.example.com`)" {
		t.Errorf("shared rule got %q", rule)
	}

	// Each replica has its own HTTP TTY router.
	if _, err := backend.Get(ctx, "traefik/http/routers/pm-tty-gw-A/rule"); err != nil {
		t.Errorf("replica A TTY router missing: %v", err)
	}
	if _, err := backend.Get(ctx, "traefik/http/routers/pm-tty-gw-B/rule"); err != nil {
		t.Errorf("replica B TTY router missing: %v", err)
	}

	// Revoking A leaves B's entries and the shared service intact.
	if err := r.RevokeTraefikRoute(ctx, "gw-A", cfgA); err != nil {
		t.Fatalf("revoke A: %v", err)
	}
	if _, err := backend.Get(ctx, "traefik/tcp/services/pm-mtls/loadbalancer/servers/gw-B/address"); err != nil {
		t.Errorf("replica B server entry must survive A's revoke: %v", err)
	}
	if _, err := backend.Get(ctx, "traefik/http/routers/pm-tty-gw-B/rule"); err != nil {
		t.Errorf("replica B TTY router must survive A's revoke: %v", err)
	}
}
