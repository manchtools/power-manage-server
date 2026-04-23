package terminal

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// ValkeyBackend is the production SessionBackend, persisting tokens
// in the same Valkey instance the control server already uses for
// RediSearch and the Asynq task queue. Keys are namespaced under
// keyPrefix and use Valkey's native TTL for expiry.
type ValkeyBackend struct {
	client *redis.Client
}

// NewValkeyBackend constructs a SessionBackend over the supplied
// go-redis client. The caller retains ownership of the client.
func NewValkeyBackend(client *redis.Client) *ValkeyBackend {
	return &ValkeyBackend{client: client}
}

// Set persists the session payload with a TTL.
func (b *ValkeyBackend) Set(ctx context.Context, sessionID string, payload []byte, ttl time.Duration) error {
	if err := b.client.Set(ctx, keyPrefix+sessionID, payload, ttl).Err(); err != nil {
		return fmt.Errorf("terminal: valkey set: %w", err)
	}
	return nil
}

// Get retrieves the raw session payload, or ErrTokenNotFound if the
// key has been evicted by TTL or never existed.
func (b *ValkeyBackend) Get(ctx context.Context, sessionID string) ([]byte, error) {
	payload, err := b.client.Get(ctx, keyPrefix+sessionID).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, ErrTokenNotFound
		}
		return nil, fmt.Errorf("terminal: valkey get: %w", err)
	}
	return payload, nil
}

// Delete removes the session entry. go-redis' DEL is idempotent: a
// missing key returns 0 affected, not an error.
func (b *ValkeyBackend) Delete(ctx context.Context, sessionID string) error {
	if err := b.client.Del(ctx, keyPrefix+sessionID).Err(); err != nil {
		return fmt.Errorf("terminal: valkey del: %w", err)
	}
	return nil
}

// GetAndDelete atomically returns the payload and removes the key in a
// single Valkey/Redis round-trip using GETDEL (available since Redis
// 6.2; redis-stack-server ships well past that). This is the primitive
// that makes terminal tokens single-use — two concurrent validators
// cannot both observe the payload.
func (b *ValkeyBackend) GetAndDelete(ctx context.Context, sessionID string) ([]byte, error) {
	payload, err := b.client.GetDel(ctx, keyPrefix+sessionID).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, ErrTokenNotFound
		}
		return nil, fmt.Errorf("terminal: valkey getdel: %w", err)
	}
	return payload, nil
}
