// Package crl is a Valkey-backed certificate revocation list shared by the
// control server (the writer) and the gateways (cached readers). Agent certs
// keep their 1-year validity, so revocation — not expiry — is what makes a
// leaked or superseded cert stop working; this list is that mechanism.
//
// Revoked fingerprints live in a single sorted set scored by the revoked cert's
// expiry (Unix seconds). That gives three things for free:
//   - the active list is one ZRANGEBYSCORE (no keyspace SCAN),
//   - entries age out on their own (a cert past its own NotAfter is rejected by
//     mTLS expiry anyway, so it never needs to stay revoked), and
//   - the gateway caches the set in memory, so the per-connection check is a
//     local map lookup — no per-connection RPC — and survives a Valkey blip.
//
// Two invariants protect the cached read path:
//   - fail-static: a refresh error KEEPS the previous snapshot (never fail-open
//     to empty), so a transient Valkey outage cannot silently drop enforcement.
//   - fail-closed-until-loaded: a Cache reports Loaded()==false until its first
//     SUCCESSFUL refresh; callers (the mTLS middleware) treat a not-yet-loaded
//     cache as "cannot prove this cert is unrevoked" and reject, distinct from a
//     loaded-but-empty cache (a genuinely empty CRL, which admits). The gateway
//     therefore fails its boot if the initial load never succeeds.
package crl

import (
	"context"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// DefaultKey is the Valkey sorted-set key holding revoked fingerprints.
const DefaultKey = "pm:crl:revoked"

// Store is the Valkey-backed CRL. The control server holds one to Revoke;
// gateways wrap one in a Cache to read.
type Store struct {
	rdb *redis.Client
	key string
	now func() time.Time
}

// Option configures a Store.
type Option func(*Store)

// WithKey overrides the sorted-set key (tests).
func WithKey(k string) Option { return func(s *Store) { s.key = k } }

// WithClock overrides the time source (tests).
func WithClock(now func() time.Time) Option { return func(s *Store) { s.now = now } }

// NewStore creates a CRL store over the given Valkey client.
func NewStore(rdb *redis.Client, opts ...Option) *Store {
	s := &Store{rdb: rdb, key: DefaultKey, now: time.Now}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Revoke records fingerprint as revoked until expiresAt (the revoked cert's
// NotAfter). An empty fingerprint or one whose cert has already expired is a
// no-op: mTLS already rejects an expired cert, so it never needs listing.
func (s *Store) Revoke(ctx context.Context, fingerprint string, expiresAt time.Time) error {
	if fingerprint == "" || !expiresAt.After(s.now()) {
		return nil
	}
	return s.rdb.ZAdd(ctx, s.key, redis.Z{
		Score:  float64(expiresAt.Unix()),
		Member: fingerprint,
	}).Err()
}

// LoadActive returns the set of fingerprints that are revoked and not yet
// expired. It also best-effort prunes already-expired members (a prune error is
// non-fatal — the score filter already excludes them from the result).
func (s *Store) LoadActive(ctx context.Context) (map[string]struct{}, error) {
	nowUnix := strconv.FormatInt(s.now().Unix(), 10)
	fps, err := s.rdb.ZRangeByScore(ctx, s.key, &redis.ZRangeBy{
		Min: nowUnix,
		Max: "+inf",
	}).Result()
	if err != nil {
		return nil, err
	}
	out := make(map[string]struct{}, len(fps))
	for _, fp := range fps {
		out[fp] = struct{}{}
	}
	// Opportunistic prune of strictly-expired members. Best-effort.
	_ = s.rdb.ZRemRangeByScore(ctx, s.key, "-inf", "("+nowUnix).Err()
	return out, nil
}

// Cache is an in-memory snapshot of the CRL for the gateway's per-connection
// fingerprint check. It refreshes from the Store on a ticker; on a refresh
// error it KEEPS the previous snapshot (fail-static, never fail-open-to-empty),
// so a transient Valkey outage cannot silently drop revocation enforcement.
//
// A freshly-constructed Cache is NOT yet loaded: Loaded() reports false until
// the first SUCCESSFUL Refresh. This is the "fail-closed until loaded at least
// once" invariant — admitting callers (the mTLS middleware) treat a not-loaded
// cache as "cannot prove this cert is unrevoked" and reject, distinct from a
// loaded-but-empty cache (a genuinely empty CRL, which admits).
type Cache struct {
	store   *Store
	logger  *slog.Logger
	mu      sync.RWMutex
	revoked map[string]struct{}
	// loaded becomes true only after the first successful Refresh and never
	// reverts: once we have ANY good snapshot, fail-static (keep it) covers
	// subsequent refresh errors. It is the boot fail-open footing — a
	// never-refreshed cache must not be mistaken for an empty revocation list.
	loaded bool
}

// NewCache creates an empty, not-yet-loaded cache over the given store.
func NewCache(store *Store, logger *slog.Logger) *Cache {
	return &Cache{store: store, logger: logger, revoked: map[string]struct{}{}}
}

// IsRevoked reports whether fingerprint is in the last loaded snapshot.
func (c *Cache) IsRevoked(fingerprint string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	_, ok := c.revoked[fingerprint]
	return ok
}

// Loaded reports whether the cache has completed at least one successful
// Refresh. False on a brand-new cache and after a refresh that only ever
// errored; true once a snapshot has been loaded (and stays true thereafter,
// per the fail-static contract).
func (c *Cache) Loaded() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.loaded
}

// Refresh reloads the snapshot from the Store. Exported so the gateway can do
// one synchronous load at startup before it starts admitting connections. On
// error the previous snapshot and the loaded flag are left unchanged (a failed
// refresh never counts as "loaded").
func (c *Cache) Refresh(ctx context.Context) error {
	next, err := c.store.LoadActive(ctx)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.revoked = next
	c.loaded = true
	c.mu.Unlock()
	return nil
}

// Run refreshes the snapshot every interval until ctx is cancelled. A refresh
// error logs and keeps the previous snapshot.
func (c *Cache) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if err := c.Refresh(ctx); err != nil {
				c.logger.Warn("CRL refresh failed; keeping previous snapshot", "error", err)
			}
		case <-ctx.Done():
			return
		}
	}
}
