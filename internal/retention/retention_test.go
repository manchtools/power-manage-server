package retention_test

import (
	"context"
	"fmt"
	"strings"
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

// TestPrune_ArchiveIsIndependentlyReplayable pins AC 22 (independent
// replay): the artifact a prune seals holds every ciphertext event ≤ N,
// recoverable from the archive bytes alone via ReadArtifact — no live
// database needed. The events ARE the snapshot: replaying them
// reconstructs state @ N. This is the offline-audit / restore contract.
func TestPrune_ArchiveIsIndependentlyReplayable(t *testing.T) {
	st := testutil.SetupPostgres(t)
	arch, err := archive.New(archive.Config{Backend: archive.BackendFilesystem, FilesystemPath: t.TempDir()})
	require.NoError(t, err)
	ctx := context.Background()

	testutil.CreateTestUser(t, st, "arc-"+testutil.NewID()[:8]+"@test.com", "pass", "admin")
	testutil.CreateTestDevice(t, st, "arc-host-"+testutil.NewID()[:6])

	w := eligibleWorker(t, st, arch)
	res, err := w.Prune(ctx)
	require.NoError(t, err)
	require.True(t, res.Pruned)

	// Read the sealed artifact back from the archive bytes alone.
	rc, err := arch.Get(ctx, res.ArchiveRef)
	require.NoError(t, err)
	defer rc.Close()
	checkpoint, events, err := retention.ReadArtifact(rc)
	require.NoError(t, err)

	// The header records checkpoint N and the archive is non-empty.
	assert.Equal(t, res.Checkpoint, checkpoint)
	assert.NotEmpty(t, events, "the archive must preserve all pruned events")

	// Every deleted event is preserved in the archive — the log ≤ N is
	// fully recoverable offline.
	assert.Len(t, events, int(res.EventsDeleted),
		"archive must hold exactly the events the prune removed from the live log")
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

func maxSeq(t *testing.T, st *store.Store) int64 {
	t.Helper()
	var n int64
	require.NoError(t, st.TestingPool().QueryRow(context.Background(),
		`SELECT COALESCE(MAX(sequence_num), 0) FROM events`).Scan(&n))
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

// TestPrune_FullCycle pins AC 16-19/28: a run archives the ciphertext
// events ≤ N and then deletes events ≤ N with an EventLogPruned marker.
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

// TestPrune_SafetyMarginProtectsRecentEvents pins the sequence-visibility
// safeguard: even with a near-zero window, the prune checkpoint may not
// reach events younger than pruneSafetyMargin (1h). sequence_num is a
// pre-commit nextval() (not commit-order-safe), so a not-yet-committed
// append could hold a lower, un-archived sequence_num; the margin keeps
// the checkpoint far enough in the past that every event at/below it has
// certainly committed. With a 1ns window and no floor this run would
// prune the just-created events; with the floor it is a no-op.
func TestPrune_SafetyMarginProtectsRecentEvents(t *testing.T) {
	// Real clock (NOT the future-clock helper): the events are seconds old,
	// so only the safety floor — not the window — can protect them.
	w, st, arch := newWorker(t, time.Nanosecond)
	ctx := context.Background()
	testutil.CreateTestUser(t, st, "recent-"+testutil.NewID()[:8]+"@test.com", "pass", "user")
	before := eventCount(t, st)

	res, err := w.Prune(ctx)
	require.NoError(t, err)
	assert.True(t, res.Ran)
	assert.False(t, res.Pruned,
		"the 1h safety margin must protect just-created events even under a 1ns window")
	assert.Zero(t, res.EventsDeleted)
	assert.Equal(t, before, eventCount(t, st), "no recent event deleted")
	assert.Zero(t, countPruned(t, st))
	infos, err := arch.List(ctx)
	require.NoError(t, err)
	assert.Empty(t, infos, "no archive written when nothing is safely prunable")
}

// TestPrune_CrashResumeIdempotent pins AC 26: a worker that crashed AFTER
// its archive landed but BEFORE the delete resumes cleanly at the SAME
// checkpoint — the deterministic ref is overwritten (not duplicated), the
// delete completes, and exactly ONE EventLogPruned is appended.
func TestPrune_CrashResumeIdempotent(t *testing.T) {
	st := testutil.SetupPostgres(t)
	arch, err := archive.New(archive.Config{Backend: archive.BackendFilesystem, FilesystemPath: t.TempDir()})
	require.NoError(t, err)
	ctx := context.Background()
	testutil.CreateTestUser(t, st, "crash-"+testutil.NewID()[:8]+"@test.com", "pass", "admin")
	testutil.CreateTestDevice(t, st, "crash-host-"+testutil.NewID()[:6])

	w := eligibleWorker(t, st, arch)
	// The checkpoint a run would choose now (future clock → all eligible).
	checkpoint := maxSeq(t, st)
	require.Positive(t, checkpoint)

	// Simulate the crash: the artifact for this checkpoint already landed
	// at its deterministic ref, but the delete never ran — events ≤ N are
	// still present and no EventLogPruned exists (the marker is appended in
	// the same tx as the delete). The stale bytes stand in for a partial
	// write the resume must overwrite.
	ref := fmt.Sprintf("prune-%020d", checkpoint) // must match the worker's ref format
	_, err = arch.Put(ctx, ref, strings.NewReader("stale partial artifact from the crashed run"))
	require.NoError(t, err)
	before := eventCount(t, st)

	// Resume: a fresh Prune re-selects the SAME checkpoint, overwrites the
	// same ref, completes the delete, and appends exactly one marker.
	res, err := w.Prune(ctx)
	require.NoError(t, err)
	require.True(t, res.Pruned)
	assert.Equal(t, checkpoint, res.Checkpoint, "resume must land on the same checkpoint")
	assert.Equal(t, ref, res.ArchiveRef, "resume must reuse the deterministic ref, not orphan a duplicate")

	assert.Equal(t, int64(1), countPruned(t, st), "exactly one EventLogPruned after the resume")
	assert.Less(t, eventCount(t, st), before, "the resume completed the delete")

	// Exactly one archive entry at the ref (the stale partial was
	// overwritten, not duplicated) and it verifies as a real sealed artifact.
	infos, err := arch.List(ctx)
	require.NoError(t, err)
	require.Len(t, infos, 1)
	assert.Equal(t, ref, infos[0].Ref)
	require.NoError(t, archive.Verify(ctx, arch, ref))
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
