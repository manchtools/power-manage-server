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
	ttyRouter := fmt.Sprintf("pm-tty-%s", gatewayID)
	ttyRule := fmt.Sprintf("Host(`%s`) && PathPrefix(`/gw/%s`)", c.TTYHost, gatewayID)
	perReplica := []struct{ key, value string }{
		{mtlsServerKey, c.MTLSBackend},
		{fmt.Sprintf("%s/http/routers/%s/rule", root, ttyRouter), ttyRule},
		{fmt.Sprintf("%s/http/routers/%s/entrypoints/0", root, ttyRouter), c.TTYEntryPoint},
		{fmt.Sprintf("%s/http/routers/%s/tls", root, ttyRouter), "true"},
		{fmt.Sprintf("%s/http/routers/%s/service", root, ttyRouter), ttyRouter},
		{fmt.Sprintf("%s/http/services/%s/loadbalancer/servers/0/url", root, ttyRouter), c.TTYBackend},
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
func (c TraefikRouteConfig) perReplicaKeys(gatewayID string) []string {
	root := c.rootKey()
	ttyRouter := fmt.Sprintf("pm-tty-%s", gatewayID)
	return []string{
		fmt.Sprintf("%s/tcp/services/pm-mtls/loadbalancer/servers/%s/address", root, gatewayID),
		fmt.Sprintf("%s/http/routers/%s/rule", root, ttyRouter),
		fmt.Sprintf("%s/http/routers/%s/entrypoints/0", root, ttyRouter),
		fmt.Sprintf("%s/http/routers/%s/tls", root, ttyRouter),
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
