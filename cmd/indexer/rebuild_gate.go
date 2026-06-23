package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"
)

// Indexer startup rebuild gate (WS13 #12). The indexer used to run a destructive
// FlushSearchData + full Rebuild on EVERY boot, so a crash-loop or concurrent
// indexers could repeatedly wipe the search index. Now:
//   - if the indexes are already present, warm-without-flush (no destructive op);
//   - otherwise acquire a Valkey lock so only ONE indexer flushes+rebuilds while
//     the others warm — concurrent boots can't race repeated destructive wipes.
const (
	rebuildLockKey = "pm:indexer:rebuild:lock"
	// rebuildLockTTL bounds how long a crashed lock holder blocks others. Longer
	// than a worst-case rebuild, but finite so a crash can't wedge rebuilds
	// forever; the holder also releases explicitly on success.
	rebuildLockTTL = 15 * time.Minute
)

// searchGate is the subset of *search.Index the startup decision needs — a seam
// so the gate logic is unit-testable without a real RediSearch backend.
type searchGate interface {
	IndexesPresent(ctx context.Context) (bool, error)
	SchemaCurrent(ctx context.Context) (bool, error)
	Warm(ctx context.Context) error
	Rebuild(ctx context.Context) error
}

// rebuildLocker coordinates the destructive rebuild across concurrent indexers.
type rebuildLocker interface {
	// TryLock attempts to acquire the rebuild lock without blocking. On success
	// it returns acquired=true and a release func; on contention acquired=false.
	TryLock(ctx context.Context) (acquired bool, release func(), err error)
}

// startupSearchSync decides how to bring the search index up at boot WITHOUT an
// unconditional destructive flush (WS13 #12):
//   - indexes present            → warm only (no flush);
//   - indexes missing, lock won  → flush + rebuild under the lock;
//   - indexes missing, lock lost → another indexer is rebuilding, so warm only.
//
// IndexesPresent failing is fatal (returned) rather than treated as "missing":
// guessing "missing" on a transient backend error would trigger an unwarranted
// destructive flush. Fail closed.
func startupSearchSync(ctx context.Context, gate searchGate, locker rebuildLocker, logger *slog.Logger) error {
	present, err := gate.IndexesPresent(ctx)
	if err != nil {
		return fmt.Errorf("check search indexes present: %w", err)
	}
	if present {
		// Present is not enough — a schema change (new field / SORTABLE) needs a
		// drop+rebuild because FT.CREATE no-ops on an existing index. Warm only
		// when the schema also matches the last rebuild's fingerprint.
		current, err := gate.SchemaCurrent(ctx)
		if err != nil {
			return fmt.Errorf("check search schema fingerprint: %w", err)
		}
		if current {
			logger.Info("search indexes present and schema current; warming without destructive flush")
			return gate.Warm(ctx)
		}
		logger.Info("search index schema changed since last rebuild; rebuild required")
	}

	acquired, release, err := locker.TryLock(ctx)
	if err != nil {
		return fmt.Errorf("acquire rebuild lock: %w", err)
	}
	if !acquired {
		logger.Info("another indexer holds the rebuild lock; warming without flush")
		return gate.Warm(ctx)
	}
	defer release()

	logger.Info("search indexes missing; performing destructive rebuild under lock")
	return gate.Rebuild(ctx)
}

// valkeyRebuildLocker is a Valkey SET NX EX rebuild lock.
type valkeyRebuildLocker struct {
	rdb   *redis.Client
	value string // unique per process so release only deletes our own lock
}

// newValkeyRebuildLocker builds a locker with a random per-process owner value.
func newValkeyRebuildLocker(rdb *redis.Client) *valkeyRebuildLocker {
	var b [16]byte
	// crypto/rand.Read never returns a short read; ignore the error per its
	// contract. A zero value would still be correct (just not unique), but a
	// random owner makes the CAS-release robust against TTL expiry races.
	_, _ = rand.Read(b[:])
	return &valkeyRebuildLocker{rdb: rdb, value: hex.EncodeToString(b[:])}
}

// casDeleteScript deletes the lock only if we still own it, so an expired-then-
// reacquired lock held by another indexer is never deleted out from under it.
const casDeleteScript = `if redis.call("get", KEYS[1]) == ARGV[1] then return redis.call("del", KEYS[1]) else return 0 end`

func (l *valkeyRebuildLocker) TryLock(ctx context.Context) (bool, func(), error) {
	ok, err := l.rdb.SetNX(ctx, rebuildLockKey, l.value, rebuildLockTTL).Result()
	if err != nil {
		return false, nil, err
	}
	if !ok {
		return false, func() {}, nil
	}
	release := func() {
		_ = l.rdb.Eval(ctx, casDeleteScript, []string{rebuildLockKey}, l.value).Err()
	}
	return true, release, nil
}
