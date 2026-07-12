package main

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/testutil"
)

// TestExpireStaleExecutions_SingleFlight pins spec 31 AC15: the stale-execution
// expiry sweep runs under a cross-replica advisory lock, so when another replica
// holds it the sweep skips (ran=false) without error — exactly one replica emits
// ExecutionTimedOut per tick.
//
// The "other replica" is simulated with a foreign session holding the lock via
// pg_try_advisory_lock, NOT st.TryWithAdvisoryLock: the latter takes a
// process-local mutex it holds across fn, so a second in-process caller would
// block on that mutex rather than exercise the CROSS-replica Postgres-lock skip.
func TestExpireStaleExecutions_SingleFlight(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	holder, err := st.TestingPool().Acquire(ctx)
	require.NoError(t, err)
	defer holder.Release()

	var got bool
	require.NoError(t, holder.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", advisoryKeyStaleExpiry).Scan(&got))
	require.True(t, got, "the foreign session must acquire the stale-expiry lock")

	ran, err := expireStaleExecutions(ctx, st, slog.Default(), time.Now)
	require.NoError(t, err)
	assert.False(t, ran, "a concurrent sweep must skip without error while another replica holds the lock")

	require.NoError(t, holder.QueryRow(ctx, "SELECT pg_advisory_unlock($1)", advisoryKeyStaleExpiry).Scan(&got))

	// With the lock free, the sweep acquires it and runs.
	ran, err = expireStaleExecutions(ctx, st, slog.Default(), time.Now)
	require.NoError(t, err)
	assert.True(t, ran, "with the lock free, the sweep runs")
}
