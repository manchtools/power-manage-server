package registry

import (
	"context"
	"strings"
	"sync"
	"time"
)

// FakeBackend is an in-memory Backend for tests so the registry
// suite doesn't need a real Valkey instance. It honours TTLs via
// lazy expiry on read against the supplied clock — pass time.Now
// in production-like tests or a frozen clock for deterministic
// expiry assertions.
//
// Concurrency is the same as the production backend: independent
// goroutines may call Set/Get/Delete simultaneously.
type FakeBackend struct {
	mu     sync.Mutex
	now    func() time.Time
	values map[string]fakeEntry
}

type fakeEntry struct {
	value     string
	expiresAt time.Time
}

// NewFakeBackend constructs an empty in-memory backend. now defaults
// to time.Now if nil.
func NewFakeBackend(now func() time.Time) *FakeBackend {
	if now == nil {
		now = time.Now
	}
	return &FakeBackend{
		now:    now,
		values: make(map[string]fakeEntry),
	}
}

// Set stores the value with the given TTL.
func (b *FakeBackend) Set(ctx context.Context, key, value string, ttl time.Duration) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.values[key] = fakeEntry{
		value:     value,
		expiresAt: b.now().Add(ttl),
	}
	return nil
}

// Get returns the stored value, honouring TTL via lazy expiry on
// read. Returns ErrNoGateway for unknown or expired entries.
func (b *FakeBackend) Get(ctx context.Context, key string) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	entry, ok := b.values[key]
	if !ok {
		return "", ErrNoGateway
	}
	if !b.now().Before(entry.expiresAt) {
		delete(b.values, key)
		return "", ErrNoGateway
	}
	return entry.value, nil
}

// Delete is idempotent.
func (b *FakeBackend) Delete(ctx context.Context, key string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.values, key)
	return nil
}

// ScanPrefix returns all non-expired key-value pairs matching the prefix.
func (b *FakeBackend) ScanPrefix(ctx context.Context, prefix string) (map[string]string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	result := make(map[string]string)
	now := b.now()
	for k, entry := range b.values {
		if !strings.HasPrefix(k, prefix) {
			continue
		}
		if !now.Before(entry.expiresAt) {
			delete(b.values, k)
			continue
		}
		result[k] = entry.value
	}
	return result, nil
}
