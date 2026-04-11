package terminal

import (
	"context"
	"sync"
	"time"
)

// FakeBackend is an in-memory SessionBackend used by tests so the
// handler suite doesn't need a real Valkey instance. It honours TTLs
// using the supplied clock — pass time.Now in production-like tests
// or a frozen clock for deterministic expiry assertions.
//
// Concurrency is the same as the production backend: independent
// goroutines may call Set/Get/Delete simultaneously.
type FakeBackend struct {
	mu     sync.Mutex
	now    func() time.Time
	values map[string]fakeEntry
}

type fakeEntry struct {
	payload   []byte
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

// Set stores the payload with the given TTL.
func (b *FakeBackend) Set(ctx context.Context, sessionID string, payload []byte, ttl time.Duration) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.values[sessionID] = fakeEntry{
		payload:   append([]byte(nil), payload...), // defensive copy
		expiresAt: b.now().Add(ttl),
	}
	return nil
}

// Get returns the stored payload, honouring TTL via lazy expiry on
// read. Returns ErrTokenNotFound for unknown or expired entries.
func (b *FakeBackend) Get(ctx context.Context, sessionID string) ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	entry, ok := b.values[sessionID]
	if !ok {
		return nil, ErrTokenNotFound
	}
	if !b.now().Before(entry.expiresAt) {
		delete(b.values, sessionID)
		return nil, ErrTokenNotFound
	}
	return append([]byte(nil), entry.payload...), nil
}

// Delete is idempotent.
func (b *FakeBackend) Delete(ctx context.Context, sessionID string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.values, sessionID)
	return nil
}
