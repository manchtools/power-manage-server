package auth

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRateLimiter_AllowWithinLimit(t *testing.T) {
	rl := NewRateLimiter(5, 1*time.Minute)

	for i := 0; i < 5; i++ {
		assert.True(t, rl.Allow("key1"), "attempt %d should be allowed", i+1)
	}
}

// TestRateLimiter_WindowUsesInjectedClock pins the sliding window against
// the injected clock: attempts age out exactly when the injected time
// advances past the window, with no dependency on the wall clock.
func TestRateLimiter_WindowUsesInjectedClock(t *testing.T) {
	now := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	rl := NewRateLimiter(2, 1*time.Minute, WithClock(func() time.Time { return now }))
	defer rl.Stop()

	assert.True(t, rl.Allow("k"), "1st attempt within window")
	assert.True(t, rl.Allow("k"), "2nd attempt within window")
	assert.False(t, rl.Allow("k"), "3rd attempt exceeds the limit within the window")

	// Advance the injected clock past the window; the earlier attempts
	// must expire by that clock, not by real elapsed time.
	now = now.Add(2 * time.Minute)
	assert.True(t, rl.Allow("k"), "attempts before the window expire by the injected clock")
	assert.True(t, rl.Allow("k"), "second post-window attempt still within new limit")
	assert.False(t, rl.Allow("k"), "limit re-applies in the new window")
}

func TestRateLimiter_BlockAfterLimit(t *testing.T) {
	rl := NewRateLimiter(3, 1*time.Minute)

	for i := 0; i < 3; i++ {
		assert.True(t, rl.Allow("key1"))
	}

	assert.False(t, rl.Allow("key1"), "should be blocked after limit")
	assert.False(t, rl.Allow("key1"), "should remain blocked")
}

func TestRateLimiter_DifferentKeysIndependent(t *testing.T) {
	rl := NewRateLimiter(2, 1*time.Minute)

	assert.True(t, rl.Allow("key1"))
	assert.True(t, rl.Allow("key1"))
	assert.False(t, rl.Allow("key1"))

	// key2 should still be allowed
	assert.True(t, rl.Allow("key2"))
	assert.True(t, rl.Allow("key2"))
	assert.False(t, rl.Allow("key2"))
}

func TestRateLimiter_WindowExpiry(t *testing.T) {
	rl := NewRateLimiter(2, 50*time.Millisecond)

	assert.True(t, rl.Allow("key1"))
	assert.True(t, rl.Allow("key1"))
	assert.False(t, rl.Allow("key1"))

	// Wait for window to expire
	time.Sleep(60 * time.Millisecond)

	assert.True(t, rl.Allow("key1"), "should be allowed after window expires")
}

func TestRateLimiter_ConcurrentAccess(t *testing.T) {
	rl := NewRateLimiter(100, 1*time.Minute)

	var wg sync.WaitGroup
	allowed := make(chan bool, 200)

	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			allowed <- rl.Allow("key1")
		}()
	}

	wg.Wait()
	close(allowed)

	trueCount := 0
	for a := range allowed {
		if a {
			trueCount++
		}
	}

	assert.Equal(t, 100, trueCount, "exactly 100 attempts should be allowed")
}

// TestRateLimiter_Blocked pins the read-only check used by the per-account
// login/TOTP ceiling: Blocked reports whether the key is at/over the limit
// WITHOUT recording an attempt, so callers can gate up front and count only the
// outcomes they choose (e.g. only failed logins).
func TestRateLimiter_Blocked(t *testing.T) {
	rl := NewRateLimiter(3, time.Minute)

	// Read-only: many Blocked calls must never record an attempt.
	for i := 0; i < 50; i++ {
		assert.False(t, rl.Blocked("k"), "Blocked must not record attempts")
	}

	rl.Allow("k") // 1
	assert.False(t, rl.Blocked("k"))
	rl.Allow("k") // 2
	assert.False(t, rl.Blocked("k"))
	rl.Allow("k") // 3 == limit
	assert.True(t, rl.Blocked("k"), "at the limit the key is blocked")

	// Keys are independent.
	assert.False(t, rl.Blocked("other"))
}

// TestRateLimiter_KeyCapEvictsEldest pins audit F-20: at the per-instance key
// ceiling, inserting a never-seen key evicts the single eldest-seen key, the
// map stays bounded (never grows to cap+1), and re-touching an EXISTING key at
// the ceiling is exempt from eviction. "Eldest" is sourced from the insertion
// order under an injected clock, not from reading evictEldestLocked's output.
func TestRateLimiter_KeyCapEvictsEldest(t *testing.T) {
	now := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	const capKeys = 4
	rl := newRateLimiterWithCap(10, time.Hour, capKeys, WithClock(func() time.Time { return now }))
	defer rl.Stop()

	// Insert `capKeys` distinct keys, advancing the clock between each so k0 is
	// provably the eldest by lastSeen and k{capKeys-1} the newest.
	for i := 0; i < capKeys; i++ {
		require.True(t, rl.Allow(fmt.Sprintf("k%d", i)))
		now = now.Add(time.Minute)
	}
	require.Len(t, rl.attempts, capKeys, "map should be exactly at the cap before the over-limit insert")

	// Insert one never-seen key at the ceiling: the eldest (k0) is evicted.
	require.True(t, rl.Allow("kNew"))
	assert.Len(t, rl.attempts, capKeys, "map must stay bounded at the cap, not grow to cap+1")
	_, k0Present := rl.attempts["k0"]
	assert.False(t, k0Present, "the eldest-seen key k0 must be the one evicted")
	_, kNewPresent := rl.attempts["kNew"]
	assert.True(t, kNewPresent, "the newly inserted key must be present after eviction")

	// Re-touch an EXISTING key at the ceiling: it gets a fresh timestamp and
	// nothing is evicted (size unchanged, no other key dropped).
	now = now.Add(time.Minute)
	require.True(t, rl.Allow("k1"))
	assert.Len(t, rl.attempts, capKeys, "re-touching an existing key must not change the map size")
	for _, k := range []string{"k1", "k2", "k3", "kNew"} {
		_, ok := rl.attempts[k]
		assert.Truef(t, ok, "existing key %q must survive an existing-key re-touch (no spurious eviction)", k)
	}
}

// TestRateLimiter_KeyCapDoesNotEvictBelowCeiling pins the rejection path: when
// the map is below the cap, inserting a new key must NOT evict anything.
func TestRateLimiter_KeyCapDoesNotEvictBelowCeiling(t *testing.T) {
	now := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	rl := newRateLimiterWithCap(10, time.Hour, 8, WithClock(func() time.Time { return now }))
	defer rl.Stop()

	for i := 0; i < 5; i++ { // 5 < cap (8)
		require.True(t, rl.Allow(fmt.Sprintf("k%d", i)))
		now = now.Add(time.Minute)
	}
	require.True(t, rl.Allow("kNew"))
	assert.Len(t, rl.attempts, 6, "no eviction below the ceiling — every inserted key is retained")
	_, k0 := rl.attempts["k0"]
	assert.True(t, k0, "k0 must NOT be evicted while the map is below the ceiling")
}
