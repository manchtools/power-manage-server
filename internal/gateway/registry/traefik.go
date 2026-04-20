package registry

// Self-registration of each gateway replica into Traefik's routing
// table via the Redis KV provider. Replaces the old per-service
// Traefik labels in compose.yml so scaling the gateway service (for
// example `docker compose up --scale gateway=3`) works with zero
// operator touch per replica.
//
// Traefik's Redis provider reads keys under a rootkey (default
// "traefik") and builds its dynamic config from them. Two kinds of
// routes are published:
//
//   * Shared TCP router for agent mTLS passthrough. All replicas
//     write the same router/service keys (identical values, so
//     concurrent writes are benign) and each adds a distinct server
//     entry under `traefik/tcp/services/pm-mtls/loadbalancer/
//     servers/<gatewayID>/address` so Traefik load-balances the pool.
//
//   * Per-replica HTTP router for TTY WebSocket traffic. Each
//     gateway writes its own router scoped to `/gw/<gatewayID>`, so
//     the control server can mint TTY tokens whose URL routes
//     deterministically to the replica holding the agent.
//
// All keys carry the same TTL as the gateway registration itself;
// the heartbeat refreshes them in lock-step with the existing
// RegisterGateway loop, and clean shutdown revokes the per-replica
// keys. The shared pm-mtls router keys expire naturally once the
// last replica goes away.

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// DefaultTraefikRootKey matches Traefik's default `--providers.redis.rootkey`
// value. Override via TraefikRouteConfig.RootKey if the deployment uses a
// different root.
const DefaultTraefikRootKey = "traefik"

// TraefikRouteConfig carries the per-gateway values needed to publish
// a complete routing entry. The caller (the gateway's main.go)
// populates this from its environment / flags.
type TraefikRouteConfig struct {
	// MTLSHost is the public HostSNI the shared TCP router matches,
	// e.g. "gateway.example.com".
	MTLSHost string
	// MTLSBackend is this replica's agent mTLS listener address,
	// e.g. "gateway-1.internal:8443". Added to the shared
	// `pm-mtls` service's load-balancer pool.
	MTLSBackend string
	// MTLSEntryPoint names the Traefik entrypoint the TCP router
	// binds to. Typically "mtls" on a dedicated port. Must be
	// defined in Traefik's static config.
	MTLSEntryPoint string
	// TTYHost is the public Host header the per-replica HTTP router
	// matches, e.g. "tty.example.com".
	TTYHost string
	// TTYBackend is this replica's TTY WebSocket listener URL,
	// e.g. "http://gateway-1.internal:8080". Traefik proxies cleartext
	// to it and handles public TLS termination itself.
	TTYBackend string
	// TTYEntryPoint is the HTTP entrypoint name, typically
	// "websecure".
	TTYEntryPoint string
	// TTYCertResolver is the Traefik certificate resolver the per-
	// replica TTY HTTP router should use to obtain its public TLS
	// cert, e.g. "letsencrypt". Matches a resolver declared in
	// Traefik's static config (`--certificatesresolvers.<name>.*`).
	//
	// Empty leaves the router with just `tls=true`, which makes
	// Traefik serve its default self-signed certificate — browsers
	// refuse that for WebSocket upgrades, so unset is only viable
	// for bring-your-own-cert setups that ship a default cert
	// pre-matched to TTYHost.
	TTYCertResolver string
	// RootKey is the Traefik Redis root-key prefix. Defaults to
	// DefaultTraefikRootKey.
	RootKey string
}

func (c TraefikRouteConfig) validate() error {
	missing := []string{}
	if c.MTLSHost == "" {
		missing = append(missing, "MTLSHost")
	}
	if c.MTLSBackend == "" {
		missing = append(missing, "MTLSBackend")
	}
	if c.MTLSEntryPoint == "" {
		missing = append(missing, "MTLSEntryPoint")
	}
	if c.TTYHost == "" {
		missing = append(missing, "TTYHost")
	}
	if c.TTYBackend == "" {
		missing = append(missing, "TTYBackend")
	}
	if c.TTYEntryPoint == "" {
		missing = append(missing, "TTYEntryPoint")
	}
	if len(missing) > 0 {
		return fmt.Errorf("registry: TraefikRouteConfig missing fields: %s", strings.Join(missing, ", "))
	}
	// TTYBackend must be an http:// URL with a non-empty host. The
	// gateway's TTY listener accepts cleartext HTTP only (public TLS
	// is terminated at Traefik); publishing an https:// backend would
	// silently produce a non-functional router — Traefik opens a
	// cleartext TCP conn to the backend, the backend expects TLS,
	// handshake fails, every WebSocket upgrade 400s. Fail fast at
	// config time instead.
	u, err := url.Parse(c.TTYBackend)
	if err != nil {
		return fmt.Errorf("registry: TTYBackend %q is not a valid URL: %w", c.TTYBackend, err)
	}
	if u.Scheme != "http" {
		return fmt.Errorf("registry: TTYBackend scheme must be \"http\" (got %q); the TTY listener is cleartext behind Traefik", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("registry: TTYBackend %q has no host", c.TTYBackend)
	}
	return nil
}

func (c TraefikRouteConfig) rootKey() string {
	if c.RootKey == "" {
		return DefaultTraefikRootKey
	}
	return c.RootKey
}

// traefikKeys builds the complete list of (key, value) pairs for a
// single gateway replica. Shared pm-mtls keys come first (all replicas
// write identical values), per-replica keys come last.
func (c TraefikRouteConfig) traefikKeys(gatewayID string) []struct{ key, value string } {
	root := c.rootKey()

	// Shared TCP router for agent mTLS. Identical across all replicas.
	sharedMTLS := []struct{ key, value string }{
		{root + "/tcp/routers/pm-mtls/rule", fmt.Sprintf("HostSNI(`%s`)", c.MTLSHost)},
		{root + "/tcp/routers/pm-mtls/entrypoints/0", c.MTLSEntryPoint},
		{root + "/tcp/routers/pm-mtls/tls/passthrough", "true"},
		{root + "/tcp/routers/pm-mtls/service", "pm-mtls"},
	}

	// Per-replica TCP server entry in the shared service.
	mtlsServerKey := fmt.Sprintf("%s/tcp/services/pm-mtls/loadbalancer/servers/%s/address", root, gatewayID)

	// Per-replica HTTP router for TTY. Unique to this gateway.
	//
	// Traefik's Redis-KV provider has two mutually exclusive ways to
	// spell "this HTTP router has TLS on":
	//
	//   a) flat:   <root>/http/routers/<r>/tls = "true"
	//   b) nested: <root>/http/routers/<r>/tls/certResolver = "<name>"
	//              (any key under /tls/ makes Traefik infer TLS on)
	//
	// The two shapes cannot coexist — Traefik's KV walker treats the
	// flat string as a scalar leaf that blocks every nested /tls/*
	// subkey underneath it, so a config that publishes both is
	// silently rejected and the router falls back to no-TLS (which
	// then fails TLS handshake on the websecure entrypoint). We
	// therefore branch on TTYCertResolver and publish one shape or
	// the other, never both:
	//
	//   * TTYCertResolver set (the normal path): write only the
	//     nested certResolver key. This is the canonical shape in
	//     Traefik's own docs for Redis-KV HTTP routers.
	//   * TTYCertResolver empty (bring-your-own-cert setups): write
	//     only the flat /tls = "true" so Traefik serves its static-
	//     config default certificate.
	ttyRouter := fmt.Sprintf("pm-tty-%s", gatewayID)
	ttyRule := fmt.Sprintf("Host(`%s`) && PathPrefix(`/gw/%s`)", c.TTYHost, gatewayID)
	perReplica := []struct{ key, value string }{
		{mtlsServerKey, c.MTLSBackend},
		{fmt.Sprintf("%s/http/routers/%s/rule", root, ttyRouter), ttyRule},
		{fmt.Sprintf("%s/http/routers/%s/entrypoints/0", root, ttyRouter), c.TTYEntryPoint},
		{fmt.Sprintf("%s/http/routers/%s/service", root, ttyRouter), ttyRouter},
		{fmt.Sprintf("%s/http/services/%s/loadbalancer/servers/0/url", root, ttyRouter), c.TTYBackend},
	}
	if c.TTYCertResolver != "" {
		perReplica = append(perReplica, struct{ key, value string }{
			fmt.Sprintf("%s/http/routers/%s/tls/certResolver", root, ttyRouter), c.TTYCertResolver,
		})
	} else {
		perReplica = append(perReplica, struct{ key, value string }{
			fmt.Sprintf("%s/http/routers/%s/tls", root, ttyRouter), "true",
		})
	}

	out := make([]struct{ key, value string }, 0, len(sharedMTLS)+len(perReplica))
	out = append(out, sharedMTLS...)
	out = append(out, perReplica...)
	return out
}

// perReplicaKeys returns only the keys owned exclusively by this gateway
// replica — the ones safe to delete on shutdown without clobbering
// other replicas' routes. Shared pm-mtls keys are NOT included; they
// expire naturally via TTL once the last replica stops refreshing them.
//
// Both TLS shapes (flat `/tls` and nested `/tls/certResolver`) are
// always listed, regardless of which one PublishTraefikRoute wrote
// this cycle: deleting a key that doesn't exist is a no-op, and
// listing both means a replica that flipped between BYO-cert and
// letsencrypt across restarts cleans up the stale shape on exit.
func (c TraefikRouteConfig) perReplicaKeys(gatewayID string) []string {
	root := c.rootKey()
	ttyRouter := fmt.Sprintf("pm-tty-%s", gatewayID)
	return []string{
		fmt.Sprintf("%s/tcp/services/pm-mtls/loadbalancer/servers/%s/address", root, gatewayID),
		fmt.Sprintf("%s/http/routers/%s/rule", root, ttyRouter),
		fmt.Sprintf("%s/http/routers/%s/entrypoints/0", root, ttyRouter),
		fmt.Sprintf("%s/http/routers/%s/tls", root, ttyRouter),
		fmt.Sprintf("%s/http/routers/%s/tls/certResolver", root, ttyRouter),
		fmt.Sprintf("%s/http/routers/%s/service", root, ttyRouter),
		fmt.Sprintf("%s/http/services/%s/loadbalancer/servers/0/url", root, ttyRouter),
	}
}

// PublishTraefikRoute writes (or refreshes) the full routing entry
// for this gateway. Call at startup and on every heartbeat tick; all
// keys carry the same TTL so a crashed replica disappears from the
// pool within the TTL window. Idempotent.
func (r *Registry) PublishTraefikRoute(ctx context.Context, gatewayID string, cfg TraefikRouteConfig, ttl time.Duration) error {
	if gatewayID == "" {
		return errors.New("registry: gatewayID is required")
	}
	if err := cfg.validate(); err != nil {
		return err
	}
	if ttl <= 0 {
		ttl = DefaultGatewayTTL
	}

	for _, pair := range cfg.traefikKeys(gatewayID) {
		if err := r.backend.Set(ctx, pair.key, pair.value, ttl); err != nil {
			return fmt.Errorf("registry: publish traefik key %q: %w", pair.key, err)
		}
	}
	return nil
}

// RevokeTraefikRoute removes the per-replica keys for this gateway so
// Traefik drops its routes immediately on clean shutdown. Shared
// pm-mtls router keys are intentionally left alone — other replicas
// may still be publishing them. Idempotent.
func (r *Registry) RevokeTraefikRoute(ctx context.Context, gatewayID string, cfg TraefikRouteConfig) error {
	if gatewayID == "" {
		return errors.New("registry: gatewayID is required")
	}
	for _, key := range cfg.perReplicaKeys(gatewayID) {
		if err := r.backend.Delete(ctx, key); err != nil {
			return fmt.Errorf("registry: revoke traefik key %q: %w", key, err)
		}
	}
	return nil
}
