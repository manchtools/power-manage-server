package terminal

import (
	"context"
	"sync"
	"time"
)

// MemoryBackend is the single-process SessionBackend. It honours TTLs using
// the supplied clock and atomically consumes one-time tokens under its mutex.
//
// Concurrency is the same as the production backend: independent
// goroutines may call Set/Get/Delete simultaneously.
type MemoryBackend struct {
	mu     sync.Mutex
	now    func() time.Time
	values map[string]memoryEntry
}

type memoryEntry struct {
	payload   []byte
	expiresAt time.Time
}

// NewMemoryBackend constructs an empty in-memory backend. now defaults
// to time.Now if nil.
func NewMemoryBackend(now func() time.Time) *MemoryBackend {
	if now == nil {
		now = time.Now
	}
	return &MemoryBackend{
		now:    now,
		values: make(map[string]memoryEntry),
	}
}

// Set stores the payload with the given TTL.
func (b *MemoryBackend) Set(ctx context.Context, sessionID string, payload []byte, ttl time.Duration) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.values[sessionID] = memoryEntry{
		payload:   append([]byte(nil), payload...), // defensive copy
		expiresAt: b.now().Add(ttl),
	}
	return nil
}

// Get returns the stored payload, honouring TTL via lazy expiry on
// read. Returns ErrTokenNotFound for unknown or expired entries.
func (b *MemoryBackend) Get(ctx context.Context, sessionID string) ([]byte, error) {
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
func (b *MemoryBackend) Delete(ctx context.Context, sessionID string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.values, sessionID)
	return nil
}

// GetAndDelete returns the payload and removes the entry in a single atomic
// step under the mutex, so
// two concurrent callers cannot both observe it. Essential for the
// single-use token semantics Validate relies on.
func (b *MemoryBackend) GetAndDelete(ctx context.Context, sessionID string) ([]byte, error) {
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
	delete(b.values, sessionID)
	return append([]byte(nil), entry.payload...), nil
}
