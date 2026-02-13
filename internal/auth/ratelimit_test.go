package auth

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRateLimiter_AllowWithinLimit(t *testing.T) {
	rl := NewRateLimiter(5, 1*time.Minute)

	for i := 0; i < 5; i++ {
		assert.True(t, rl.Allow("key1"), "attempt %d should be allowed", i+1)
	}
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
