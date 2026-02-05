package auth

import (
	"sync"
	"time"
)

// RateLimiter implements a sliding window rate limiter.
// It tracks attempts per key (e.g., IP address) and rejects requests
// that exceed the configured limit within the time window.
type RateLimiter struct {
	mu       sync.Mutex
	attempts map[string][]time.Time
	limit    int
	window   time.Duration
}

// NewRateLimiter creates a new rate limiter that allows limit attempts
// per key within the given time window. A background goroutine cleans
// up stale entries periodically.
func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		attempts: make(map[string][]time.Time),
		limit:    limit,
		window:   window,
	}
	go rl.cleanup()
	return rl
}

// Allow returns true if the key has not exceeded the rate limit.
// Each call to Allow counts as an attempt.
func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
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
		return false
	}

	rl.attempts[key] = append(valid, now)
	return true
}

// cleanup periodically removes stale entries from the attempts map.
func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		rl.mu.Lock()
		cutoff := time.Now().Add(-rl.window)
		for key, attempts := range rl.attempts {
			valid := attempts[:0]
			for _, t := range attempts {
				if t.After(cutoff) {
					valid = append(valid, t)
				}
			}
			if len(valid) == 0 {
				delete(rl.attempts, key)
			} else {
				rl.attempts[key] = valid
			}
		}
		rl.mu.Unlock()
	}
}
