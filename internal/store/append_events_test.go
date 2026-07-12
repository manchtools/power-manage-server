package store_test

// AppendEvents (spec 28) — transactional multi-stream batch append.
// Each test maps to a numbered acceptance criterion. Testcontainer-backed
// because atomicity, versioning and the post-commit listener path only
// run behind a real Postgres transaction; a mocked Queries would bypass
// every guarantee under test.
//
// The forced-failure cases use Store.TestingSetInsertHook — the
// spec-sanctioned test-only seam (the spec's "export_test hook that fails
// the Nth insert"). Returning a plain error models a mid-batch DB fault
// (AC 2); returning store.ErrVersionConflict models a lost optimistic-
// concurrency race and drives the whole-batch retry (AC 5).

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/eventtypes/payloads"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

func sysEvent(streamType, streamID, eventType string) store.Event {
	return store.Event{
		StreamType: streamType,
		StreamID:   streamID,
		EventType:  eventType,
		Data:       map[string]any{},
		ActorType:  "system",
		ActorID:    "test",
	}
}

// AC 1 — a batch across distinct streams commits atomically: every row
// present, each fresh stream at version 1, sequence_num ascending in
// array order.
func TestAppendEvents_AtomicCommitAcrossStreams(t *testing.T) {
	st := testutil.SetupPostgresWithoutProjectors(t)
	ctx := context.Background()

	sA, sB, sC := testutil.NewID(), testutil.NewID(), testutil.NewID()
	require.NoError(t, st.AppendEvents(ctx, []store.Event{
		sysEvent("test_a", sA, "E1"),
		sysEvent("test_b", sB, "E2"),
		sysEvent("test_c", sC, "E3"),
	}))

	evA, err := st.LoadStream(ctx, "test_a", sA)
	require.NoError(t, err)
	evB, err := st.LoadStream(ctx, "test_b", sB)
	require.NoError(t, err)
	evC, err := st.LoadStream(ctx, "test_c", sC)
	require.NoError(t, err)

	require.Len(t, evA, 1)
	require.Len(t, evB, 1)
	require.Len(t, evC, 1)

	assert.Equal(t, int32(1), evA[0].StreamVersion, "fresh stream starts at version 1")
	assert.Equal(t, int32(1), evB[0].StreamVersion)
	assert.Equal(t, int32(1), evC[0].StreamVersion)

	assert.Less(t, evA[0].SequenceNum, evB[0].SequenceNum, "sequence_num ascends in array order")
	assert.Less(t, evB[0].SequenceNum, evC[0].SequenceNum)
}

// AC 2 — when the Kth event cannot be written, the whole batch rolls
// back: no event from any target stream is present.
func TestAppendEvents_AllOrNothingOnFailure(t *testing.T) {
	st := testutil.SetupPostgresWithoutProjectors(t)
	ctx := context.Background()

	sA, sB, sC := testutil.NewID(), testutil.NewID(), testutil.NewID()
	// Fail the second event's insert; the first is already inserted in the
	// same tx and must be discarded on rollback.
	st.TestingSetInsertHook(func(streamType, eventType string) error {
		if streamType == "test_b" {
			return errors.New("synthetic mid-batch insert failure")
		}
		return nil
	})

	err := st.AppendEvents(ctx, []store.Event{
		sysEvent("test_a", sA, "E1"),
		sysEvent("test_b", sB, "E2"),
		sysEvent("test_c", sC, "E3"),
	})
	require.Error(t, err)

	for _, s := range []struct{ typ, id string }{{"test_a", sA}, {"test_b", sB}, {"test_c", sC}} {
		ev, lerr := st.LoadStream(ctx, s.typ, s.id)
		require.NoError(t, lerr)
		assert.Empty(t, ev, "stream %s must be empty — a failed batch writes nothing", s.typ)
	}
}

// AC 2 (rejection-paths row 1) — an event missing actor_type/actor_id
// fails the batch before any write, so nothing lands.
func TestAppendEvents_MissingActorWritesNothing(t *testing.T) {
	st := testutil.SetupPostgresWithoutProjectors(t)
	ctx := context.Background()

	sA := testutil.NewID()
	err := st.AppendEvents(ctx, []store.Event{
		sysEvent("test_a", sA, "E1"),
		{StreamType: "test_b", StreamID: testutil.NewID(), EventType: "E2", Data: map[string]any{}}, // no actor
	})
	require.Error(t, err)

	ev, lerr := st.LoadStream(ctx, "test_a", sA)
	require.NoError(t, lerr)
	assert.Empty(t, ev, "a batch containing an invalid event writes nothing")
}

// AC 3 — two events on the same stream get consecutive versions: the
// second's in-tx version read observes the first's insert.
func TestAppendEvents_SameStreamConsecutiveVersions(t *testing.T) {
	st := testutil.SetupPostgresWithoutProjectors(t)
	ctx := context.Background()
	id := testutil.NewID()

	require.NoError(t, st.AppendEvents(ctx, []store.Event{
		sysEvent("test", id, "First"),
		sysEvent("test", id, "Second"),
	}))

	ev, err := st.LoadStream(ctx, "test", id)
	require.NoError(t, err)
	require.Len(t, ev, 2)
	assert.Equal(t, int32(1), ev[0].StreamVersion)
	assert.Equal(t, int32(2), ev[1].StreamVersion)
	assert.Equal(t, "First", ev[0].EventType)
	assert.Equal(t, "Second", ev[1].EventType)
}

// AC 4 — listeners fire once per event, in array order, and only after
// the whole batch has committed (a listener reading the store observes
// every event, never a partial set).
func TestAppendEvents_ListenersFirePostCommitInOrder(t *testing.T) {
	st := testutil.SetupPostgresWithoutProjectors(t)
	ctx := context.Background()

	sA, sB := testutil.NewID(), testutil.NewID()
	var (
		mu   sync.Mutex
		seen []string
	)
	st.RegisterEventListener(func(ctx context.Context, ev store.PersistedEvent) {
		// Both streams are already committed by the time any listener runs.
		evA, _ := st.LoadStream(ctx, "test_a", sA)
		evB, _ := st.LoadStream(ctx, "test_b", sB)
		mu.Lock()
		seen = append(seen, ev.EventType)
		mu.Unlock()
		assert.Len(t, evA, 1, "listener must see a committed batch, not a partial one")
		assert.Len(t, evB, 1, "listener must see a committed batch, not a partial one")
	})

	require.NoError(t, st.AppendEvents(ctx, []store.Event{
		sysEvent("test_a", sA, "First"),
		sysEvent("test_b", sB, "Second"),
	}))

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, []string{"First", "Second"}, seen,
		"listeners fire once per event, in array (sequence) order")
}

// AC 4 — a panicking listener does not fail the already-durable batch,
// and subsequent listeners still fire.
func TestAppendEvents_ListenerPanicDoesNotFailBatch(t *testing.T) {
	st := testutil.SetupPostgresWithoutProjectors(t)
	ctx := context.Background()
	id := testutil.NewID()

	var after atomic.Bool
	st.RegisterEventListener(func(ctx context.Context, ev store.PersistedEvent) { panic("synthetic listener panic") })
	st.RegisterEventListener(func(ctx context.Context, ev store.PersistedEvent) { after.Store(true) })

	require.NoError(t, st.AppendEvents(ctx, []store.Event{sysEvent("test", id, "PanicProbe")}),
		"a panicking listener must not fail an already-committed batch")
	assert.True(t, after.Load(), "listener after a panicking one must still fire")

	ev, err := st.LoadStream(ctx, "test", id)
	require.NoError(t, err)
	assert.Len(t, ev, 1, "the batch is durable even though a listener panicked")
}

// AC 4 (end-to-end) — a batch drives the REAL projection path
// (fireListeners → Go listener → projection write), not just a recording
// fake. The load-bearing guarantee now that PL/pgSQL projection is gone.
func TestAppendEvents_DrivesRealProjector(t *testing.T) {
	st := testutil.SetupPostgres(t) // wires the production Go projectors
	ctx := context.Background()

	gA, gB := testutil.NewID(), testutil.NewID()
	require.NoError(t, st.AppendEvents(ctx, []store.Event{
		{StreamType: "user_group", StreamID: gA, EventType: string(eventtypes.UserGroupCreated),
			Data: payloads.UserGroupCreated{Name: "Group A", Description: "batch a"}, ActorType: "system", ActorID: "test"},
		{StreamType: "user_group", StreamID: gB, EventType: string(eventtypes.UserGroupCreated),
			Data: payloads.UserGroupCreated{Name: "Group B", Description: "batch b"}, ActorType: "system", ActorID: "test"},
	}))

	grpA, err := st.Repos().UserGroup.Get(ctx, gA)
	require.NoError(t, err)
	assert.Equal(t, "Group A", grpA.Name, "projection must reflect the first batch event")
	grpB, err := st.Repos().UserGroup.Get(ctx, gB)
	require.NoError(t, err)
	assert.Equal(t, "Group B", grpB.Name, "projection must reflect the second batch event")
}

// AC 5 — a version conflict retries the WHOLE transaction (re-reading
// versions) and still commits atomically once the race clears; no
// duplicate rows from the rolled-back attempts.
func TestAppendEvents_RetriesWholeBatchAndConverges(t *testing.T) {
	st := testutil.SetupPostgresWithoutProjectors(t)
	ctx := context.Background()
	sA, sB := testutil.NewID(), testutil.NewID()

	// Lose the race on the 2nd event for the first two attempts, then win.
	var conflicts int32
	st.TestingSetInsertHook(func(streamType, eventType string) error {
		if streamType == "test_b" && atomic.AddInt32(&conflicts, 1) <= 2 {
			return store.ErrVersionConflict
		}
		return nil
	})

	require.NoError(t, st.AppendEvents(ctx, []store.Event{
		sysEvent("test_a", sA, "E1"),
		sysEvent("test_b", sB, "E2"),
	}))

	evA, err := st.LoadStream(ctx, "test_a", sA)
	require.NoError(t, err)
	evB, err := st.LoadStream(ctx, "test_b", sB)
	require.NoError(t, err)
	assert.Len(t, evA, 1, "rolled-back attempts leave no duplicate on the first stream")
	assert.Len(t, evB, 1)
	assert.Equal(t, int32(1), evA[0].StreamVersion)
	assert.Equal(t, int32(1), evB[0].StreamVersion)
}

// AC 5 (deadlock variant) — a Postgres deadlock (40P01) aborts the whole
// transaction; like a version conflict it is transient, so the batch
// retries the whole tx and converges. Two overlapping multi-stream
// batches locking the same streams in opposite orders are the real
// trigger; a synthetic 40P01 injected via the seam pins the
// classification deterministically (a real concurrent deadlock is
// timing-flaky and would race the CI).
func TestAppendEvents_RetriesOnDeadlockAndConverges(t *testing.T) {
	st := testutil.SetupPostgresWithoutProjectors(t)
	ctx := context.Background()
	sA, sB := testutil.NewID(), testutil.NewID()

	var deadlocks int32
	st.TestingSetInsertHook(func(streamType, eventType string) error {
		if streamType == "test_b" && atomic.AddInt32(&deadlocks, 1) == 1 {
			return &pgconn.PgError{Code: "40P01", Message: "deadlock detected"}
		}
		return nil
	})

	require.NoError(t, st.AppendEvents(ctx, []store.Event{
		sysEvent("test_a", sA, "E1"),
		sysEvent("test_b", sB, "E2"),
	}), "a transient deadlock must be retried, not surfaced")

	evA, err := st.LoadStream(ctx, "test_a", sA)
	require.NoError(t, err)
	evB, err := st.LoadStream(ctx, "test_b", sB)
	require.NoError(t, err)
	assert.Len(t, evA, 1, "the rolled-back first attempt leaves no duplicate")
	assert.Len(t, evB, 1)
}

// AC 5 — a conflict that never clears exhausts the retry budget and
// returns ErrVersionConflict having written nothing.
func TestAppendEvents_UnresolvableConflictWritesNothing(t *testing.T) {
	st := testutil.SetupPostgresWithoutProjectors(t)
	ctx := context.Background()
	sA, sB := testutil.NewID(), testutil.NewID()

	st.TestingSetInsertHook(func(streamType, eventType string) error {
		if streamType == "test_b" {
			return store.ErrVersionConflict
		}
		return nil
	})

	err := st.AppendEvents(ctx, []store.Event{
		sysEvent("test_a", sA, "E1"),
		sysEvent("test_b", sB, "E2"),
	})
	require.Error(t, err)
	assert.True(t, store.IsVersionConflict(err),
		"an unresolvable conflict must surface ErrVersionConflict to the caller")

	evA, lerr := st.LoadStream(ctx, "test_a", sA)
	require.NoError(t, lerr)
	assert.Empty(t, evA, "nothing is written when the batch cannot converge")
}

// AC 6 — an event whose PII subject has no minted DEK makes sealing fail;
// since sealing runs before the transaction, the batch writes nothing.
func TestAppendEvents_PIISealFailClosed(t *testing.T) {
	st := testutil.SetupPostgres(t) // wires the fail-closed PII sealer
	ctx := context.Background()

	benignStream := testutil.NewID()
	userWithoutDEK := testutil.NewID() // never MintUserDEK'd → seal fails

	name := "Should Not Persist"
	err := st.AppendEvents(ctx, []store.Event{
		sysEvent("test", benignStream, "Benign"),
		{StreamType: "user", StreamID: userWithoutDEK, EventType: string(eventtypes.UserProfileUpdated),
			Data: payloads.UserProfileUpdated{DisplayName: &name}, ActorType: "system", ActorID: "test"},
	})
	require.Error(t, err, "an event whose subject has no DEK must fail the batch")

	ev, lerr := st.LoadStream(ctx, "test", benignStream)
	require.NoError(t, lerr)
	assert.Empty(t, ev, "seal failure aborts before any DB write — the benign event must not persist")
}

// AC 7 — a single-element batch behaves like AppendEvent (fresh stream at
// v1, one row, monotonic on a second call).
func TestAppendEvents_SingleElementMatchesAppendEvent(t *testing.T) {
	st := testutil.SetupPostgresWithoutProjectors(t)
	ctx := context.Background()
	id := testutil.NewID()

	require.NoError(t, st.AppendEvents(ctx, []store.Event{sysEvent("test", id, "Solo")}))
	ev, err := st.LoadStream(ctx, "test", id)
	require.NoError(t, err)
	require.Len(t, ev, 1)
	assert.Equal(t, int32(1), ev[0].StreamVersion)
	assert.Equal(t, "Solo", ev[0].EventType)

	require.NoError(t, st.AppendEvents(ctx, []store.Event{sysEvent("test", id, "Solo2")}))
	ev, err = st.LoadStream(ctx, "test", id)
	require.NoError(t, err)
	require.Len(t, ev, 2)
	assert.Equal(t, int32(2), ev[1].StreamVersion)
}

// Spec 29 S9 — sealPII fails CLOSED: an event carrying PII-tagged fields appended
// to a store with NO sealer wired is refused, never written as plaintext to the
// immutable log. A store without projectors has no sealer, so this exercises the
// fail-closed path directly.
func TestSealPII_FailsClosedWithoutSealer(t *testing.T) {
	st := testutil.SetupPostgresWithoutProjectors(t) // no PII sealer wired
	ctx := context.Background()
	name := "Secret Display Name"
	err := st.AppendEvent(ctx, store.Event{
		StreamType: "user",
		StreamID:   testutil.NewID(),
		EventType:  string(eventtypes.UserProfileUpdated),
		Data:       payloads.UserProfileUpdated{DisplayName: &name}, // DisplayName is pii:"true"
		ActorType:  "system",
		ActorID:    "test",
	})
	require.Error(t, err, "a PII event with no sealer wired must fail closed")
	require.Contains(t, err.Error(), "sealer")
}

// Spec 29 S9 — a NON-PII event still appends fine without a sealer (bootstrap /
// low-level store paths that predate the wiring are unaffected).
func TestSealPII_NonPIIEventAppendsWithoutSealer(t *testing.T) {
	st := testutil.SetupPostgresWithoutProjectors(t)
	ctx := context.Background()
	require.NoError(t, st.AppendEvent(ctx, sysEvent("test", testutil.NewID(), "NoPII")))
}

// Spec 29 S8 — AppendEventWithVersion (the OCC append path) must reject an event
// with no actor, like AppendEvent/AppendEvents. The DB columns default to ” so
// without this check an unattributable event would silently persist.
func TestAppendEventWithVersion_RejectsMissingActor(t *testing.T) {
	st := testutil.SetupPostgresWithoutProjectors(t)
	ctx := context.Background()
	err := st.AppendEventWithVersion(ctx, store.Event{
		StreamType: "test",
		StreamID:   testutil.NewID(),
		EventType:  "NoActor",
		Data:       map[string]any{},
		// no ActorType / ActorID
	}, 1)
	require.Error(t, err, "AppendEventWithVersion must reject an event with no actor")
	require.Contains(t, err.Error(), "actor")
}

// AC 7 — an empty/nil batch is a no-op returning nil.
func TestAppendEvents_EmptyIsNoOp(t *testing.T) {
	st := testutil.SetupPostgresWithoutProjectors(t)
	ctx := context.Background()
	assert.NoError(t, st.AppendEvents(ctx, nil))
	assert.NoError(t, st.AppendEvents(ctx, []store.Event{}))
}
