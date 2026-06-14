package main

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/crl"
)

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// TestGatewayBoot_InitialCRLLoadFailureIsFatal pins WS12 #1: the gateway boot
// path treats an initial CRL load error as fatal (returns a non-nil error the
// caller os.Exit(1)s on) rather than continuing to ListenAndServeTLS with an
// unloaded, empty revocation list.
func TestGatewayBoot_InitialCRLLoadFailureIsFatal(t *testing.T) {
	t.Run("successful load → nil, cache loaded (boot proceeds)", func(t *testing.T) {
		mr := miniredis.RunT(t)
		rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
		t.Cleanup(func() { _ = rdb.Close() })
		cache := crl.NewCache(crl.NewStore(rdb), quietLogger())

		err := loadInitialCRL(context.Background(), cache, 3, time.Millisecond, quietLogger())
		require.NoError(t, err)
		assert.True(t, cache.Loaded(),
			"after a successful initial load the cache MUST report loaded — no boot path may continue with Loaded()==false")
	})

	t.Run("backend down → non-nil error (caller exits, never admits)", func(t *testing.T) {
		mr := miniredis.RunT(t)
		rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
		t.Cleanup(func() { _ = rdb.Close() })
		mr.Close() // backend unreachable → every Refresh errors
		cache := crl.NewCache(crl.NewStore(rdb), quietLogger())

		err := loadInitialCRL(context.Background(), cache, 3, time.Millisecond, quietLogger())
		require.Error(t, err, "an initial CRL load that never succeeds MUST surface a fatal error, not be swallowed")
		assert.False(t, cache.Loaded(), "a failed initial load must leave the cache not-loaded (the middleware then fails closed)")
	})

	t.Run("cancelled context aborts the retry loop", func(t *testing.T) {
		mr := miniredis.RunT(t)
		rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
		t.Cleanup(func() { _ = rdb.Close() })
		mr.Close()
		cache := crl.NewCache(crl.NewStore(rdb), quietLogger())

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // already cancelled (SIGTERM during startup)
		err := loadInitialCRL(ctx, cache, 5, time.Hour, quietLogger())
		require.Error(t, err, "a cancelled startup context must abort the retry loop promptly, not block on backoff")
	})
}
