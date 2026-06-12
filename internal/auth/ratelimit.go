package auth

import (
	"sync"
	"time"
)

// maxRateLimiterKeys caps the size of the per-key attempts map
// (audit F-20). A distributed attacker sending one request each from
// many distinct IPs would otherwise grow the map unbounded between
// cleanup ticks (every 5 minutes). 100k entries is the per-instance
// ceiling — beyond that the eldest-seen entry is evicted to make
// room. Set high enough that legitimate IP diversity (a CDN front,
// large multi-tenant deployment) doesn't bump into it.
const maxRateLimiterKeys = 100_000

// RateLimiter implements a sliding window rate limiter.
// It tracks attempts per key (e.g., IP address) and rejects requests
// that exceed the configured limit within the time window.
type RateLimiter struct {
	mu       sync.Mutex
	attempts map[string][]time.Time
	// lastSeen tracks the most recent attempt timestamp per key so
	// the LRU eviction in Allow can pick the truly stalest entry
	// without re-scanning the attempts slices. Kept in lock-step
	// with attempts — every write to attempts updates this map too.
	lastSeen map[string]time.Time
	limit    int
	window   time.Duration
	stopCh   chan struct{}
	now      func() time.Time // clock seam; defaults to time.Now, overridden in tests
}

// RateLimiterOption configures a RateLimiter.
type RateLimiterOption func(*RateLimiter)

// WithClock overrides the time source (tests). The default is time.Now.
func WithClock(now func() time.Time) RateLimiterOption {
	return func(rl *RateLimiter) { rl.now = now }
}

// NewRateLimiter creates a new rate limiter that allows limit attempts
// per key within the given time window. A background goroutine cleans
// up stale entries periodically.
func NewRateLimiter(limit int, window time.Duration, opts ...RateLimiterOption) *RateLimiter {
	rl := &RateLimiter{
		attempts: make(map[string][]time.Time),
		lastSeen: make(map[string]time.Time),
		limit:    limit,
		window:   window,
		stopCh:   make(chan struct{}),
		now:      time.Now,
	}
	for _, opt := range opts {
		opt(rl)
	}
	go rl.cleanup()
	return rl
}

// Allow returns true if the key has not exceeded the rate limit.
// Each call to Allow counts as an attempt.
func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := rl.now()
	cutoff := now.Add(-rl.window)

	// Remove expired entries
	attempts := rl.attempts[key]
	valid := attempts[:0]
	for _, t := range attempts {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}

	if len(valid) >= rl.limit {
		rl.attempts[key] = valid
		rl.lastSeen[key] = now
		return false
	}

	// Enforce the per-instance key cap before insertion. If we're at
	// the ceiling AND this is a never-seen-before key, evict the
	// eldest entry. Existing keys are exempt — they just get a fresh
	// timestamp.
	if _, exists := rl.attempts[key]; !exists && len(rl.attempts) >= maxRateLimiterKeys {
		rl.evictEldestLocked()
	}

	rl.attempts[key] = append(valid, now)
	rl.lastSeen[key] = now
	return true
}

// Blocked reports whether key is already at or over the limit within the
// current window, WITHOUT recording an attempt. Use it to gate an action up
// front, then call Allow only on the outcomes you want to count (e.g. record
// only failed logins, so successful logins never accrue toward a per-account
// brute-force ceiling).
func (rl *RateLimiter) Blocked(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	cutoff := rl.now().Add(-rl.window)
	valid := 0
	for _, t := range rl.attempts[key] {
		if t.After(cutoff) {
			valid++
		}
	}
	return valid >= rl.limit
}

// evictEldestLocked removes the single key with the oldest lastSeen
// timestamp. Caller must hold rl.mu. O(n) scan — only called on the
// rare path where the map is at the key ceiling, so the cost lives in
// the attack scenario rather than the happy path.
func (rl *RateLimiter) evictEldestLocked() {
	var eldestKey string
	var eldestAt time.Time
	for k, t := range rl.lastSeen {
		if eldestKey == "" || t.Before(eldestAt) {
			eldestKey = k
			eldestAt = t
		}
	}
	if eldestKey != "" {
		delete(rl.attempts, eldestKey)
		delete(rl.lastSeen, eldestKey)
	}
}

// Stop stops the background cleanup goroutine.
func (rl *RateLimiter) Stop() {
	close(rl.stopCh)
}

// cleanup periodically removes stale entries from the attempts map.
func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			rl.mu.Lock()
			cutoff := rl.now().Add(-rl.window)
			for key, attempts := range rl.attempts {
				valid := attempts[:0]
				for _, t := range attempts {
					if t.After(cutoff) {
						valid = append(valid, t)
					}
				}
				if len(valid) == 0 {
					delete(rl.attempts, key)
					delete(rl.lastSeen, key)
				} else {
					rl.attempts[key] = valid
				}
			}
			rl.mu.Unlock()
		case <-rl.stopCh:
			return
		}
	}
}
