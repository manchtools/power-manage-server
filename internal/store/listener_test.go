package store_test

// Listener-semantics tests for the post-commit hook the projector
// wave plumbs through Store.RegisterEventListener. The contract is
// documented inline on EventListener in store.go:
//
//   - listeners fire after AppendEvent commits, in registration order
//   - a panicking listener does not break subsequent listeners or the
//     AppendEvent caller's success return
//   - the persisted event row (sequence_num populated) is what
//     listeners receive, not the in-flight Event the caller built
//
// These are testcontainer-backed because the listener path runs only
// behind a real commit — fireListeners is invoked from inside
// AppendEvent / AppendEventWithVersion after the sqlc Queries.AppendEvent
// query returns. A mocked Queries would silently bypass the listener.

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// TestEventListener_FiresInRegistrationOrder asserts the documented
// contract: listeners are invoked in the order they were registered.
// A regression here would scramble projector cascades — e.g. the
// search-index listener depends on the projection-write listener
// having already run.
func TestEventListener_FiresInRegistrationOrder(t *testing.T) {
	st := testutil.SetupPostgresWithoutProjectors(t)
	ctx := context.Background()

	var (
		mu   sync.Mutex
		seen []string
	)
	record := func(name string) store.EventListener {
		return func(ctx context.Context, ev store.PersistedEvent) {
			mu.Lock()
			defer mu.Unlock()
			seen = append(seen, name)
		}
	}
	st.RegisterEventListener(record("first"))
	st.RegisterEventListener(record("second"))
	st.RegisterEventListener(record("third"))

	err := st.AppendEvent(ctx, store.Event{
		StreamType: "test",
		StreamID:   testutil.NewID(),
		EventType:  "OrderingProbe",
		Data:       map[string]any{},
		ActorType:  "system",
		ActorID:    "test",
	})
	require.NoError(t, err)

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, []string{"first", "second", "third"}, seen,
		"listeners must fire in registration order — projector cascades depend on it")
}

// TestEventListener_PanicIsolation asserts the post-commit-notification
// contract: AppendEvent returns success even when a listener panics,
// and the panic does not stop subsequent listeners. The persisted
// event is durable; listener failures are best-effort by design (the
// reconciler is the safety net).
func TestEventListener_PanicIsolation(t *testing.T) {
	st := testutil.SetupPostgresWithoutProjectors(t)
	ctx := context.Background()

	var afterPanic atomic.Bool

	st.RegisterEventListener(func(ctx context.Context, ev store.PersistedEvent) {
		panic("synthetic listener panic")
	})
	st.RegisterEventListener(func(ctx context.Context, ev store.PersistedEvent) {
		afterPanic.Store(true)
	})

	err := st.AppendEvent(ctx, store.Event{
		StreamType: "test",
		StreamID:   testutil.NewID(),
		EventType:  "PanicProbe",
		Data:       map[string]any{},
		ActorType:  "system",
		ActorID:    "test",
	})
	require.NoError(t, err, "AppendEvent must return success even when a listener panics")
	assert.True(t, afterPanic.Load(),
		"listener after a panicking one must still fire — panic isolation is per-listener, not per-event")
}

// TestEventListener_ReceivesPersistedRow asserts that listeners
// receive the row as written to the events table — sequence_num must
// be populated (PG SERIAL value) so downstream consumers like the
// search-index listener can use it as a stable ordering key.
func TestEventListener_ReceivesPersistedRow(t *testing.T) {
	st := testutil.SetupPostgresWithoutProjectors(t)
	ctx := context.Background()

	var captured store.PersistedEvent
	done := make(chan struct{})
	st.RegisterEventListener(func(ctx context.Context, ev store.PersistedEvent) {
		captured = ev
		close(done)
	})

	streamID := testutil.NewID()
	err := st.AppendEvent(ctx, store.Event{
		StreamType: "test",
		StreamID:   streamID,
		EventType:  "PersistProbe",
		Data:       map[string]any{"k": "v"},
		ActorType:  "system",
		ActorID:    "test",
	})
	require.NoError(t, err)
	<-done

	assert.Equal(t, "test", captured.StreamType)
	assert.Equal(t, streamID, captured.StreamID)
	assert.Equal(t, "PersistProbe", captured.EventType)
	require.NotNil(t, captured.SequenceNum,
		"persisted event must carry a non-nil SequenceNum — listeners depend on it for ordering")
	assert.Greater(t, *captured.SequenceNum, int64(0))
	assert.NotZero(t, captured.OccurredAt,
		"OccurredAt is set server-side; listeners receive the persisted value, not the caller's zero time")
}

// TestAppendEventWithVersion_ConflictWrapsSentinel locks in the wave-H
// contract: conflict failures wrap store.ErrVersionConflict so callers
// can route through errors.Is / store.IsVersionConflict instead of
// matching error strings. The existing TestAppendEventWithVersion_Conflict
// only asserts the legacy substring form; this test guards the typed
// path that Wave I+ callers (e.g. the SCIM idempotent retry layer)
// will depend on.
func TestAppendEventWithVersion_ConflictWrapsSentinel(t *testing.T) {
	st := testutil.SetupPostgresWithoutProjectors(t)
	ctx := context.Background()
	id := testutil.NewID()

	err := st.AppendEventWithVersion(ctx, store.Event{
		StreamType: "test",
		StreamID:   id,
		EventType:  "TestCreated",
		Data:       map[string]any{},
		ActorType:  "system",
		ActorID:    "test",
	}, 1)
	require.NoError(t, err)

	err = st.AppendEventWithVersion(ctx, store.Event{
		StreamType: "test",
		StreamID:   id,
		EventType:  "TestUpdated",
		Data:       map[string]any{},
		ActorType:  "system",
		ActorID:    "test",
	}, 1)
	require.Error(t, err)
	assert.True(t, errors.Is(err, store.ErrVersionConflict),
		"conflict error must wrap store.ErrVersionConflict so callers can use errors.Is")
	assert.True(t, store.IsVersionConflict(err),
		"store.IsVersionConflict must classify the wrapped error")
}

// TestAppendEvent_ConflictRetriesAndRecovers asserts the inner retry
// loop in AppendEvent (auto-versioning path) recovers from a race
// without surfacing ErrVersionConflict to the caller — the caller
// didn't pin an expected version, so a re-read + retry is the
// documented behaviour. Without this guard, a regression that turned
// retries into immediate failures would silently break every handler
// that uses AppendEvent (most of them).
func TestAppendEvent_ConflictRetriesAndRecovers(t *testing.T) {
	st := testutil.SetupPostgresWithoutProjectors(t)
	ctx := context.Background()

	id := testutil.NewID()

	// Seed: one event on the stream so subsequent AppendEvent reads
	// stream_version=1 and tries to append at version=2.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "test",
		StreamID:   id,
		EventType:  "Seed",
		Data:       map[string]any{},
		ActorType:  "system",
		ActorID:    "test",
	}))

	const goroutines = 5
	var wg sync.WaitGroup
	errs := make(chan error, goroutines)
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			errs <- st.AppendEvent(ctx, store.Event{
				StreamType: "test",
				StreamID:   id,
				EventType:  "RaceProbe",
				Data:       map[string]any{},
				ActorType:  "system",
				ActorID:    "test",
			})
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		assert.NoError(t, err,
			"AppendEvent must transparently retry on version conflict — the auto-version path is the documented happy path")
	}
}
