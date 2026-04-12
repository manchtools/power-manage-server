package registry

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// ValkeyBackend is the production Backend, persisting registry
// entries in the same Valkey instance the gateway and control server
// already use for the Asynq task queue and (on control) RediSearch.
type ValkeyBackend struct {
	client *redis.Client
}

// NewValkeyBackend constructs a Backend over the supplied go-redis
// client. The caller retains ownership of the client.
func NewValkeyBackend(client *redis.Client) *ValkeyBackend {
	return &ValkeyBackend{client: client}
}

// Set persists value under key with a TTL.
func (b *ValkeyBackend) Set(ctx context.Context, key, value string, ttl time.Duration) error {
	if err := b.client.Set(ctx, key, value, ttl).Err(); err != nil {
		return fmt.Errorf("registry: valkey set: %w", err)
	}
	return nil
}

// Get retrieves the stored value, or ErrNoGateway if the key has
// been evicted by TTL or never existed.
func (b *ValkeyBackend) Get(ctx context.Context, key string) (string, error) {
	val, err := b.client.Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return "", ErrNoGateway
		}
		return "", fmt.Errorf("registry: valkey get: %w", err)
	}
	return val, nil
}

// Delete removes the key. go-redis' DEL is idempotent: a missing
// key returns 0 affected, not an error.
func (b *ValkeyBackend) Delete(ctx context.Context, key string) error {
	if err := b.client.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("registry: valkey del: %w", err)
	}
	return nil
}
