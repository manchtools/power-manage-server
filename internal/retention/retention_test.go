package retention_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/archive"
	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/eventtypes/payloads"
	"github.com/manchtools/power-manage/server/internal/retention"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

func newWorker(t *testing.T, window time.Duration) (*retention.Worker, *store.Store, archive.ArchiveStore) {
	t.Helper()
	st := testutil.SetupPostgres(t)
	arch, err := archive.New(archive.Config{Backend: archive.BackendFilesystem, FilesystemPath: t.TempDir()})
	require.NoError(t, err)
	w, err := retention.NewWorker(st, arch, retention.Config{Window: window}, nil)
	require.NoError(t, err)
	return w, st, arch
}

// eligibleWorker returns a worker whose clock is far in the FUTURE, so
// every already-seeded event is older than a 1h window and thus prune-
// eligible (positive window, as production requires).
func eligibleWorker(t *testing.T, st *store.Store, arch archive.ArchiveStore) *retention.Worker {
	t.Helper()
	w, err := retention.NewWorker(st, arch, retention.Config{Window: time.Hour}, nil)
	require.NoError(t, err)
	future := time.Now().Add(1000 * time.Hour)
	w.SetNowForTest(func() time.Time { return future })
	return w
}

func securityAlertCount(t *testing.T, st *store.Store) int64 {
	t.Helper()
	var n int64
	require.NoError(t, st.TestingPool().QueryRow(context.Background(),
		`SELECT COUNT(*) FROM security_alerts_projection`).Scan(&n))
	return n
}

// TestPrune_WithSecurityAlert_DoesNotViolateFK pins the retention
// prerequisite that a projection must never pin the prunable log:
// security_alerts_projection.event_id used to FK-reference events(id)
// with NO ON DELETE, so pruning the raising event (≤ N) failed the
// DELETE with a foreign-key violation. Migration 012 drops that FK; the
// alert row (derived state) survives the prune with a now-dangling
// event_id reference, exactly like any other projection whose source
// events have aged into the cold archive.
func TestPrune_WithSecurityAlert_DoesNotViolateFK(t *testing.T) {
	st := testutil.SetupPostgres(t)
	arch, err := archive.New(archive.Config{Backend: archive.BackendFilesystem, FilesystemPath: t.TempDir()})
	require.NoError(t, err)
	ctx := context.Background()

	deviceID := testutil.CreateTestDevice(t, st, "alert-host-"+testutil.NewID()[:6])
	// Raise a security alert on the device stream. The listener writes a
	// security_alerts_projection row whose event_id references THIS event
	// in the log — the event the prune is about to delete.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "device",
		StreamID:   deviceID,
		EventType:  string(eventtypes.SecurityAlert),
		Data: payloads.SecurityAlert{
			AlertType: "intrusion",
			Message:   "unexpected root login",
		},
		ActorType: "system",
		ActorID:   "gateway",
	}))
	require.Positive(t, securityAlertCount(t, st), "the alert projection row must land")

	w := eligibleWorker(t, st, arch)
	res, err := w.Prune(ctx)
	require.NoError(t, err, "prune must not fail on the security-alert → events FK")
	require.True(t, res.Pruned)

	// The alert row survives — it is derived state, not the log.
	assert.Positive(t, securityAlertCount(t, st),
		"pruning the raising event must not delete the derived alert row")
}

func eventCount(t *testing.T, st *store.Store) int64 {
	t.Helper()
	var n int64
	require.NoError(t, st.TestingPool().QueryRow(context.Background(),
		`SELECT COUNT(*) FROM events`).Scan(&n))
	return n
}

func countPruned(t *testing.T, st *store.Store) int64 {
	t.Helper()
	var n int64
	require.NoError(t, st.TestingPool().QueryRow(context.Background(),
		`SELECT COUNT(*) FROM events WHERE event_type = 'EventLogPruned'`).Scan(&n))
	return n
}

// backdateAllEvents pushes every existing event's occurred_at into the
// past so a short retention window makes them prune-eligible. Done via a
// direct UPDATE bypassing the append-only trigger is impossible, so we
// instead use a wide-enough negative window in the worker; this helper
// exists for the no-op test to keep events "recent".

// TestPrune_FullCycle pins AC 16-19/28: a run archives {snapshot,
// events ≤ N} and then deletes events ≤ N with an EventLogPruned marker.
func TestPrune_FullCycle(t *testing.T) {
	st := testutil.SetupPostgres(t)
	arch, err := archive.New(archive.Config{Backend: archive.BackendFilesystem, FilesystemPath: t.TempDir()})
	require.NoError(t, err)
	ctx := context.Background()

	testutil.CreateTestUser(t, st, "ret-"+testutil.NewID()[:8]+"@test.com", "pass", "admin")
	testutil.CreateTestDevice(t, st, "ret-host-"+testutil.NewID()[:6])
	before := eventCount(t, st)
	require.Positive(t, before)

	w := eligibleWorker(t, st, arch)
	res, err := w.Prune(ctx)
	require.NoError(t, err)
	assert.True(t, res.Ran, "the run acquired the single-flight lock")
	assert.True(t, res.Pruned)
	assert.Positive(t, res.EventsDeleted)
	assert.NotEmpty(t, res.ArchiveRef)

	// EventLogPruned appended; log shrank.
	assert.Equal(t, int64(1), countPruned(t, st))
	assert.Less(t, eventCount(t, st), before)

	// Archive landed and is sealed/verifiable (AC 22/28: durable before delete).
	infos, err := arch.List(ctx)
	require.NoError(t, err)
	require.Len(t, infos, 1)
	assert.Equal(t, res.ArchiveRef, infos[0].Ref)
	require.NoError(t, archive.Verify(ctx, arch, res.ArchiveRef))
}

// TestPrune_NoOp pins AC 25: with a window that leaves nothing older
// than it, a run makes no deletion, writes no archive, appends no
// EventLogPruned.
func TestPrune_NoOp(t *testing.T) {
	// Large positive window → cutoff far in the past → nothing eligible.
	w, st, arch := newWorker(t, 100*365*24*time.Hour)
	ctx := context.Background()
	testutil.CreateTestUser(t, st, "noop-"+testutil.NewID()[:8]+"@test.com", "pass", "user")
	before := eventCount(t, st)

	res, err := w.Prune(ctx)
	require.NoError(t, err)
	assert.True(t, res.Ran)
	assert.False(t, res.Pruned, "no-op run: nothing older than the window")
	assert.Zero(t, res.EventsDeleted)

	assert.Equal(t, before, eventCount(t, st), "no event deleted")
	assert.Zero(t, countPruned(t, st), "no EventLogPruned appended")
	infos, err := arch.List(ctx)
	require.NoError(t, err)
	assert.Empty(t, infos, "no archive written on a no-op")
}

// TestPrune_CrashResumeIdempotent pins AC 26: re-running at the same
// checkpoint (e.g. the worker crashed after the archive landed but
// before/around the delete) completes exactly one prune — the deleted
// range is already gone, the archive ref is deterministic, and the
// EventLogPruned count does not double.
func TestPrune_CrashResumeIdempotent(t *testing.T) {
	st := testutil.SetupPostgres(t)
	arch, err := archive.New(archive.Config{Backend: archive.BackendFilesystem, FilesystemPath: t.TempDir()})
	require.NoError(t, err)
	ctx := context.Background()
	testutil.CreateTestUser(t, st, "crash-"+testutil.NewID()[:8]+"@test.com", "pass", "admin")

	w := eligibleWorker(t, st, arch)
	res1, err := w.Prune(ctx)
	require.NoError(t, err)
	require.True(t, res1.Pruned)

	// A second immediate run: everything eligible is already pruned, so
	// the new checkpoint is the EventLogPruned marker's own seq or
	// beyond — but EventLogPruned is excluded from the checkpoint, so
	// the next checkpoint covers only whatever remains. Re-running must
	// not corrupt: at most one more prune, no duplicate archive for the
	// same ref, EventLogPruned count grows by at most one.
	prunedBefore := countPruned(t, st)
	res2, err := w.Prune(ctx)
	require.NoError(t, err)
	_ = res2
	assert.LessOrEqual(t, countPruned(t, st)-prunedBefore, int64(1),
		"a resume must not double-prune the same checkpoint")

	// Archives never duplicate a ref.
	infos, err := arch.List(ctx)
	require.NoError(t, err)
	seen := map[string]bool{}
	for _, i := range infos {
		assert.False(t, seen[i.Ref], "no duplicate archive ref")
		seen[i.Ref] = true
	}
}

// TestPrune_SingleFlight pins AC 27: while one prune holds the advisory
// lock, a concurrent call returns Ran=false and does nothing.
func TestPrune_SingleFlight(t *testing.T) {
	st := testutil.SetupPostgres(t)
	arch, err := archive.New(archive.Config{Backend: archive.BackendFilesystem, FilesystemPath: t.TempDir()})
	require.NoError(t, err)
	ctx := context.Background()
	testutil.CreateTestUser(t, st, "sf-"+testutil.NewID()[:8]+"@test.com", "pass", "user")
	w := eligibleWorker(t, st, arch)

	// Simulate "another replica" holding the prune lock on a SEPARATE
	// session — a raw pool connection, NOT st.TryWithAdvisoryLock. The
	// latter takes a process-local mutex it holds across fn, so a second
	// in-process caller would block on that mutex (serialize) instead of
	// skipping; the pg_try_advisory_lock skip is the CROSS-replica path,
	// which only a foreign session reproduces.
	const pruneKey int64 = 0x7072756e65 // == advisoryKeyPrune
	holder, err := st.TestingPool().Acquire(ctx)
	require.NoError(t, err)
	defer holder.Release()
	var got bool
	require.NoError(t, holder.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", pruneKey).Scan(&got))
	require.True(t, got, "holder session must acquire the prune lock")

	res, err := w.Prune(ctx)
	require.NoError(t, err)
	assert.False(t, res.Ran, "a concurrent prune must skip without error (single-flight)")
	assert.False(t, res.Pruned)

	require.NoError(t, holder.QueryRow(ctx, "SELECT pg_advisory_unlock($1)", pruneKey).Scan(&got))
}
