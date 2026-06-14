package crl

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testStore(t *testing.T, now func() time.Time) (*Store, *miniredis.Miniredis, *redis.Client) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return NewStore(rdb, WithKey("test:crl"), WithClock(now)), mr, rdb
}

func TestStore_RevokeAndLoadActive(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	s, _, _ := testStore(t, func() time.Time { return now })

	require.NoError(t, s.Revoke(context.Background(), "fp-a", now.Add(time.Hour)))
	require.NoError(t, s.Revoke(context.Background(), "fp-b", now.Add(24*time.Hour)))

	active, err := s.LoadActive(context.Background())
	require.NoError(t, err)
	assert.Contains(t, active, "fp-a")
	assert.Contains(t, active, "fp-b")
}

func TestStore_RevokeAlreadyExpiredIsNoop(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	s, _, _ := testStore(t, func() time.Time { return now })

	// A cert that already expired never needs revoking — mTLS rejects it anyway.
	require.NoError(t, s.Revoke(context.Background(), "fp-old", now.Add(-time.Minute)))
	require.NoError(t, s.Revoke(context.Background(), "", now.Add(time.Hour))) // empty fp no-op

	active, err := s.LoadActive(context.Background())
	require.NoError(t, err)
	assert.Empty(t, active)
}

func TestStore_LoadActiveExcludesAndPrunesExpired(t *testing.T) {
	cur := time.Unix(1_000_000, 0)
	s, _, rdb := testStore(t, func() time.Time { return cur })

	require.NoError(t, s.Revoke(context.Background(), "fp-short", cur.Add(time.Minute)))
	require.NoError(t, s.Revoke(context.Background(), "fp-long", cur.Add(time.Hour)))

	// Advance the clock past fp-short's expiry.
	cur = cur.Add(2 * time.Minute)

	active, err := s.LoadActive(context.Background())
	require.NoError(t, err)
	assert.NotContains(t, active, "fp-short", "expired revocation must not be returned")
	assert.Contains(t, active, "fp-long")

	// The expired member was pruned from the sorted set.
	card, err := rdb.ZCard(context.Background(), "test:crl").Result()
	require.NoError(t, err)
	assert.Equal(t, int64(1), card, "expired member should have been pruned")
}

func TestCache_IsRevokedAfterRefresh(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	s, _, _ := testStore(t, func() time.Time { return now })
	require.NoError(t, s.Revoke(context.Background(), "fp-x", now.Add(time.Hour)))

	c := NewCache(s, slog.Default())
	assert.False(t, c.IsRevoked("fp-x"), "empty cache before refresh")
	require.NoError(t, c.Refresh(context.Background()))
	assert.True(t, c.IsRevoked("fp-x"))
	assert.False(t, c.IsRevoked("fp-unknown"))
}

// TestCache_NotLoadedUntilFirstSuccessfulRefresh pins WS12 #1/#3: the
// "loaded vs never-loaded" distinction that the mTLS fail-closed gate keys on.
// Sourced from intent ("fail closed until the list has loaded at least once"),
// NOT from the revoked==nil/empty artifact.
func TestCache_NotLoadedUntilFirstSuccessfulRefresh(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	s, mr, _ := testStore(t, func() time.Time { return now })

	c := NewCache(s, slog.Default())
	// ABSENT: a brand-new cache with no Refresh is NOT loaded (boot fail-open
	// footing) — distinct from "loaded and empty".
	assert.False(t, c.Loaded(), "a never-refreshed cache must report not-loaded")

	// present-but-WRONG: a refresh against a closed backend errors → still not
	// loaded (a FAILED refresh does not count as loaded).
	mr.Close()
	require.Error(t, c.Refresh(context.Background()))
	assert.False(t, c.Loaded(), "a failed refresh must not flip Loaded() to true")
}

func TestCache_LoadedTrueAfterSuccessfulRefresh(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	s, _, _ := testStore(t, func() time.Time { return now })

	c := NewCache(s, slog.Default())
	require.NoError(t, c.Refresh(context.Background()))
	assert.True(t, c.Loaded(), "after one successful Refresh the cache is loaded")
	// loaded-and-empty is a valid state: the CRL had no entries, but the cache
	// IS loaded, so the gate admits non-revoked certs.
	assert.False(t, c.IsRevoked("anything"))
}

func TestCache_FailStaticOnRefreshError(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	s, mr, _ := testStore(t, func() time.Time { return now })
	require.NoError(t, s.Revoke(context.Background(), "fp-x", now.Add(time.Hour)))

	c := NewCache(s, slog.Default())
	require.NoError(t, c.Refresh(context.Background()))
	require.True(t, c.IsRevoked("fp-x"))

	// Valkey goes away — a refresh now errors, but the cache must KEEP the last
	// good snapshot rather than fail open to an empty (no-revocations) set.
	mr.Close()
	require.Error(t, c.Refresh(context.Background()))
	assert.True(t, c.IsRevoked("fp-x"), "must retain the previous snapshot on a refresh error")
	// WS12 #1: after a successful load, a later failed refresh keeps Loaded()
	// true (fail-static) — the two states (never-loaded vs loaded-then-stale)
	// must not collapse.
	assert.True(t, c.Loaded(), "a failed refresh after a good load must keep Loaded() true (fail-static)")
}
