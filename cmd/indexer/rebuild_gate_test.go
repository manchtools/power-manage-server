package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func gateTestLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

type fakeGate struct {
	present      bool
	presentErr   error
	warmCalls    int
	rebuildCalls int
}

func (f *fakeGate) IndexesPresent(context.Context) (bool, error) { return f.present, f.presentErr }
func (f *fakeGate) Warm(context.Context) error                   { f.warmCalls++; return nil }
func (f *fakeGate) Rebuild(context.Context) error                { f.rebuildCalls++; return nil }

type fakeLocker struct {
	acquired bool
	err      error
	released int
}

func (f *fakeLocker) TryLock(context.Context) (bool, func(), error) {
	return f.acquired, func() { f.released++ }, f.err
}

// TestStartupSearchSync_GatesDestructiveRebuild pins WS13 #12: the destructive
// flush+rebuild only happens when the indexes are MISSING and this indexer wins
// the lock; otherwise it warms without flushing. A present-check error fails
// closed (no flush).
func TestStartupSearchSync_GatesDestructiveRebuild(t *testing.T) {
	ctx := context.Background()

	t.Run("indexes present → warm only, never rebuild", func(t *testing.T) {
		g := &fakeGate{present: true}
		l := &fakeLocker{acquired: true} // would acquire, but must not be consulted
		require.NoError(t, startupSearchSync(ctx, g, l, gateTestLogger()))
		assert.Equal(t, 1, g.warmCalls, "present indexes must be warmed")
		assert.Equal(t, 0, g.rebuildCalls, "present indexes must NOT be destructively rebuilt")
	})

	t.Run("indexes missing + lock won → rebuild under lock", func(t *testing.T) {
		g := &fakeGate{present: false}
		l := &fakeLocker{acquired: true}
		require.NoError(t, startupSearchSync(ctx, g, l, gateTestLogger()))
		assert.Equal(t, 1, g.rebuildCalls, "missing indexes + lock held → rebuild")
		assert.Equal(t, 0, g.warmCalls)
		assert.Equal(t, 1, l.released, "the lock must be released after rebuild")
	})

	t.Run("indexes missing + lock lost → warm only (no racing wipe)", func(t *testing.T) {
		g := &fakeGate{present: false}
		l := &fakeLocker{acquired: false}
		require.NoError(t, startupSearchSync(ctx, g, l, gateTestLogger()))
		assert.Equal(t, 1, g.warmCalls, "a contender that lost the lock warms instead of flushing")
		assert.Equal(t, 0, g.rebuildCalls, "only the lock holder may flush+rebuild")
	})

	t.Run("present-check error fails closed (no flush)", func(t *testing.T) {
		g := &fakeGate{presentErr: errors.New("backend down")}
		l := &fakeLocker{acquired: true}
		require.Error(t, startupSearchSync(ctx, g, l, gateTestLogger()),
			"a present-check error must be fatal, not treated as 'missing' (which would flush)")
		assert.Equal(t, 0, g.rebuildCalls, "must NOT flush/rebuild on an indeterminate present-check")
		assert.Equal(t, 0, g.warmCalls)
	})
}

// TestValkeyRebuildLocker_TryLock pins the SET NX EX mutual exclusion: a second
// indexer cannot acquire while the lock is held, and the lock is reacquirable
// after the holder releases it (CAS-delete).
func TestValkeyRebuildLocker_TryLock(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	ctx := context.Background()

	l1 := newValkeyRebuildLocker(rdb)
	l2 := newValkeyRebuildLocker(rdb)
	require.NotEqual(t, l1.value, l2.value, "each locker has a distinct owner value")

	ok1, release1, err := l1.TryLock(ctx)
	require.NoError(t, err)
	require.True(t, ok1, "the first indexer acquires the lock")

	ok2, _, err := l2.TryLock(ctx)
	require.NoError(t, err)
	require.False(t, ok2, "a second indexer must NOT acquire while the lock is held")

	release1()

	ok3, release3, err := l2.TryLock(ctx)
	require.NoError(t, err)
	require.True(t, ok3, "the lock is reacquirable after the holder releases it")
	release3()
}
