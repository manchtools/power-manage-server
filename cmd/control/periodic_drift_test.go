package main

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// testDriftGrace is a near-zero recheck grace for the DB-backed tests: the
// induced drift is permanent (a raw event the projectors never applied), so the
// recheck sees it in both scans regardless of grace — a tiny grace just keeps
// the test fast. The false-positive suppression itself is proven deterministically
// by the rescreenDrift unit tests below.
const testDriftGrace = time.Millisecond

// TestRunProjectionDriftCheck_DetectsDrift pins M1 (TG4): the scheduled
// drift-reconcile tick runs the scan under the advisory lock and reports a
// projection that has silently stopped applying events it should. A healthy
// store reports ran=true with no drift; after a raw event is injected past a
// projection's high-water (a direct INSERT fires no post-commit listener, the
// exact silent-drop this worker exists to surface), the same tick reports the
// lagging target.
func TestRunProjectionDriftCheck_DetectsDrift(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	testutil.CreateTestUser(t, st, "drift-tick-"+testutil.NewID()[:8]+"@test.com", "pass", "admin")
	testutil.CreateTestDevice(t, st, "drift-tick-host-"+testutil.NewID()[:6])

	// Healthy: the live listeners kept every projection current, so the tick
	// runs (lock free) and finds nothing.
	ran, drifted, err := runProjectionDriftCheck(ctx, st, slog.Default(), testDriftGrace)
	require.NoError(t, err)
	require.True(t, ran, "with the lock free the drift check must run")
	assert.Empty(t, drifted, "a healthy store has no drifted projections")

	// Induce drift on the user stream: a raw event the projectors never
	// applied. Its type is UserCreatedWithRoles — one the users projection has
	// demonstrably applied before — so it is a real silently-dropped write, not
	// a co-tenant event of a shared stream. Mirrors the store-level
	// observability_test drift induction.
	_, err = st.TestingPool().Exec(ctx, `
		INSERT INTO events (id, stream_type, stream_id, stream_version, event_type, data, metadata, actor_type, actor_id)
		VALUES ($1, 'user', $2, 1, 'UserCreatedWithRoles', '{}', '{}', 'system', 'drift-tick-test')`,
		testutil.NewID(), "ghost-"+testutil.NewID()[:8])
	require.NoError(t, err)

	ran, drifted, err = runProjectionDriftCheck(ctx, st, slog.Default(), testDriftGrace)
	require.NoError(t, err)
	require.True(t, ran)
	require.NotEmpty(t, drifted, "the injected unapplied event must surface as drift")

	var users *store.TargetDrift
	for i := range drifted {
		if drifted[i].Target == "users" {
			users = &drifted[i]
		}
		assert.True(t, drifted[i].Drifted(), "every returned target must actually be Behind")
	}
	require.NotNil(t, users, "the users projection must be reported as drifted")
	assert.NotEmpty(t, users.LaggingTable, "a drifted target names the lagging table")
}

// TestRunProjectionDriftCheck_SingleFlight pins the cross-replica single-flight
// (M1): the scan runs under advisoryKeyProjectionDrift, so when another replica
// holds the lock the tick skips (ran=false) without error — exactly one replica
// scans per tick.
//
// The "other replica" is a foreign session holding the lock via
// pg_try_advisory_lock, NOT st.TryWithAdvisoryLock (which takes a process-local
// mutex across fn, so a second in-process caller would block on the mutex rather
// than exercise the CROSS-replica Postgres-lock skip).
func TestRunProjectionDriftCheck_SingleFlight(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	holder, err := st.TestingPool().Acquire(ctx)
	require.NoError(t, err)
	defer holder.Release()

	var got bool
	require.NoError(t, holder.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", advisoryKeyProjectionDrift).Scan(&got))
	require.True(t, got, "the foreign session must acquire the drift-check lock")

	ran, drifted, err := runProjectionDriftCheck(ctx, st, slog.Default(), testDriftGrace)
	require.NoError(t, err)
	assert.False(t, ran, "a concurrent scan must skip without error while another replica holds the lock")
	assert.Empty(t, drifted, "a skipped scan reports no drift")

	require.NoError(t, holder.QueryRow(ctx, "SELECT pg_advisory_unlock($1)", advisoryKeyProjectionDrift).Scan(&got))

	// With the lock free, the scan acquires it and runs.
	ran, _, err = runProjectionDriftCheck(ctx, st, slog.Default(), testDriftGrace)
	require.NoError(t, err)
	assert.True(t, ran, "with the lock free, the scan runs")
}

// behindTarget builds a Behind TargetDrift for the rescreen unit tests.
func behindTarget(name string) store.TargetDrift {
	return store.TargetDrift{Target: name, Behind: true, LaggingTable: name + "_projection", LaggingMax: 1}
}

// scriptedDrift returns a compute func that yields the supplied per-call results
// in order; the last entry repeats if called more than len(results) times.
func scriptedDrift(results ...[]store.TargetDrift) func(context.Context) ([]store.TargetDrift, error) {
	call := 0
	return func(context.Context) ([]store.TargetDrift, error) {
		r := results[call]
		if call < len(results)-1 {
			call++
		}
		return r, nil
	}
}

// TestRescreenDrift_TransientNotReported is the regression test for the
// post-commit apply race: a committed event is visible before its projector
// apply finishes, so a single scan can read a healthy projection as behind. The
// first scan sees "users" behind (mid-apply); by the grace recheck it has caught
// up. The tick must NOT alert — the recheck separates transient apply-lag from a
// stopped projector. (Fails on the pre-fix single-scan implementation.)
func TestRescreenDrift_TransientNotReported(t *testing.T) {
	compute := scriptedDrift(
		[]store.TargetDrift{behindTarget("users")}, // first scan: mid-apply
		nil, // recheck: caught up
	)
	confirmed, err := rescreenDrift(context.Background(), compute, time.Millisecond)
	require.NoError(t, err)
	assert.Empty(t, confirmed, "transient drift that clears by the recheck must not be reported")
}

// TestRescreenDrift_PersistentReported pins the true-positive: a projection
// behind in BOTH scans is a genuinely stopped projector and is reported.
func TestRescreenDrift_PersistentReported(t *testing.T) {
	compute := scriptedDrift(
		[]store.TargetDrift{behindTarget("users")},
		[]store.TargetDrift{behindTarget("users")},
	)
	confirmed, err := rescreenDrift(context.Background(), compute, time.Millisecond)
	require.NoError(t, err)
	require.Len(t, confirmed, 1)
	assert.Equal(t, "users", confirmed[0].Target)
}

// TestRescreenDrift_CleanFirstScanSkipsRecheck pins the fast path: a clean first
// scan returns immediately without re-scanning. The call-count assertion detects
// an unexpected recheck directly (calls would be 2), so the short grace is used —
// a regressed fast path fails promptly instead of stalling CI.
func TestRescreenDrift_CleanFirstScanSkipsRecheck(t *testing.T) {
	calls := 0
	compute := func(context.Context) ([]store.TargetDrift, error) {
		calls++
		return nil, nil
	}
	confirmed, err := rescreenDrift(context.Background(), compute, testDriftGrace)
	require.NoError(t, err)
	assert.Empty(t, confirmed)
	assert.Equal(t, 1, calls, "a clean first scan must skip the grace wait and the recheck")
}

// TestRescreenDrift_NewDriftInSecondScanNotReported pins the intersection
// direction: drift that appears only in the recheck (e.g. itself a fresh
// mid-apply) is not yet corroborated, so it is not reported — only drift present
// in BOTH scans alerts.
func TestRescreenDrift_NewDriftInSecondScanNotReported(t *testing.T) {
	compute := scriptedDrift(
		[]store.TargetDrift{behindTarget("users")},
		[]store.TargetDrift{behindTarget("users"), behindTarget("devices")},
	)
	confirmed, err := rescreenDrift(context.Background(), compute, time.Millisecond)
	require.NoError(t, err)
	require.Len(t, confirmed, 1)
	assert.Equal(t, "users", confirmed[0].Target, "only drift present in both scans is reported")
}
