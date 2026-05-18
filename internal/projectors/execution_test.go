package projectors_test

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/projectors"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// ============================================================================
// Pure-function decoder tests.
// ============================================================================

func TestExecutionCreatedFromEvent_Pure(t *testing.T) {
	t.Run("happy path with all fields", func(t *testing.T) {
		executedAt := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)
		got, err := projectors.ExecutionCreatedFromEvent(store.PersistedEvent{
			StreamType: "execution", StreamID: "exec-1", EventType: "ExecutionCreated",
			ActorType: "user", ActorID: "u-1",
			Data: jsonOrFail(t, map[string]any{
				"device_id":       "dev-1",
				"action_id":       "act-1",
				"action_type":     5,
				"desired_state":   1,
				"params":          map[string]any{"k": "v"},
				"timeout_seconds": 60,
				"executed_at":     executedAt,
			}),
		})
		require.NoError(t, err)
		assert.Equal(t, "exec-1", got.ID)
		assert.Equal(t, "dev-1", got.DeviceID)
		require.NotNil(t, got.ActionID)
		assert.Equal(t, "act-1", *got.ActionID)
		assert.Equal(t, int32(5), got.ActionType)
		assert.Equal(t, int32(1), got.DesiredState)
		assert.JSONEq(t, `{"k":"v"}`, string(got.Params))
		assert.Equal(t, int32(60), got.TimeoutSeconds)
		assert.Equal(t, "user", got.CreatedByType)
		assert.Equal(t, "u-1", got.CreatedByID)
		assert.True(t, got.CreatedAt.Equal(time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)))
	})

	t.Run("defaults: missing desired_state, params, timeout_seconds, executed_at", func(t *testing.T) {
		occurredAt := time.Date(2026, 2, 2, 0, 0, 0, 0, time.UTC)
		got, err := projectors.ExecutionCreatedFromEvent(store.PersistedEvent{
			StreamType: "execution", StreamID: "exec-2", EventType: "ExecutionCreated",
			ActorType: "user", ActorID: "u",
			OccurredAt: occurredAt,
			Data: jsonOrFail(t, map[string]any{
				"device_id":   "dev-1",
				"action_id":   "act-1",
				"action_type": 0,
			}),
		})
		require.NoError(t, err)
		assert.Equal(t, int32(0), got.DesiredState)
		assert.Equal(t, []byte(`{}`), got.Params, "params defaults to empty JSONB object")
		assert.Equal(t, int32(300), got.TimeoutSeconds)
		assert.True(t, got.CreatedAt.Equal(occurredAt), "missing executed_at falls back to event.occurred_at")
	})

	t.Run("definition_id falls back when action_id is absent", func(t *testing.T) {
		got, err := projectors.ExecutionCreatedFromEvent(store.PersistedEvent{
			StreamType: "execution", StreamID: "exec-3", EventType: "ExecutionCreated",
			ActorType: "user", ActorID: "u",
			Data: jsonOrFail(t, map[string]any{
				"device_id":     "dev-1",
				"definition_id": "def-1",
				"action_type":   3,
			}),
		})
		require.NoError(t, err)
		require.NotNil(t, got.ActionID)
		assert.Equal(t, "def-1", *got.ActionID, "PL/pgSQL COALESCE(action_id, definition_id) preserved")
	})

	t.Run("device_id is required", func(t *testing.T) {
		_, err := projectors.ExecutionCreatedFromEvent(store.PersistedEvent{
			StreamType: "execution", StreamID: "exec-4", EventType: "ExecutionCreated",
			ActorType: "user", ActorID: "u",
			Data: jsonOrFail(t, map[string]any{"action_type": 1}),
		})
		require.Error(t, err)
		assert.False(t, errors.Is(err, projectors.ErrIgnoredEvent))
		assert.Contains(t, err.Error(), "device_id")
	})

	t.Run("action_type is required", func(t *testing.T) {
		_, err := projectors.ExecutionCreatedFromEvent(store.PersistedEvent{
			StreamType: "execution", StreamID: "exec-5", EventType: "ExecutionCreated",
			ActorType: "user", ActorID: "u",
			Data: jsonOrFail(t, map[string]any{"device_id": "dev-1"}),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "action_type")
	})

	t.Run("wrong stream/event_type → ErrIgnoredEvent", func(t *testing.T) {
		_, err := projectors.ExecutionCreatedFromEvent(store.PersistedEvent{
			StreamType: "user", EventType: "ExecutionCreated",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
		_, err = projectors.ExecutionCreatedFromEvent(store.PersistedEvent{
			StreamType: "execution", EventType: "ExecutionDispatched",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})

	t.Run("malformed payload bytes is a validation error", func(t *testing.T) {
		_, err := projectors.ExecutionCreatedFromEvent(store.PersistedEvent{
			StreamType: "execution", EventType: "ExecutionCreated",
			Data: []byte("not json"),
		})
		require.Error(t, err)
		assert.False(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})
}

func TestExecutionScheduledFromEvent_Pure(t *testing.T) {
	scheduledFor := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)

	t.Run("happy path", func(t *testing.T) {
		got, err := projectors.ExecutionScheduledFromEvent(store.PersistedEvent{
			StreamType: "execution", StreamID: "exec-1", EventType: "ExecutionScheduled",
			ActorType: "user", ActorID: "u-1",
			Data: jsonOrFail(t, map[string]any{
				"device_id":     "dev-1",
				"action_id":     "act-1",
				"action_type":   2,
				"scheduled_for": scheduledFor,
			}),
		})
		require.NoError(t, err)
		assert.Equal(t, "dev-1", got.DeviceID)
		assert.True(t, got.ScheduledFor.Equal(time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)))
	})

	t.Run("scheduled_for is required", func(t *testing.T) {
		_, err := projectors.ExecutionScheduledFromEvent(store.PersistedEvent{
			StreamType: "execution", StreamID: "exec-2", EventType: "ExecutionScheduled",
			ActorType: "user", ActorID: "u",
			Data: jsonOrFail(t, map[string]any{
				"device_id": "dev-1", "action_type": 1,
			}),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "scheduled_for")
	})

	t.Run("wrong stream/event_type → ErrIgnoredEvent", func(t *testing.T) {
		_, err := projectors.ExecutionScheduledFromEvent(store.PersistedEvent{
			StreamType: "execution", EventType: "ExecutionCreated",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})
}

func TestExecutionCompletedFromEvent_Pure(t *testing.T) {
	t.Run("happy path with full result payload", func(t *testing.T) {
		completedAt := time.Date(2026, 4, 4, 4, 4, 4, 0, time.UTC).Format(time.RFC3339Nano)
		got, err := projectors.ExecutionCompletedFromEvent(store.PersistedEvent{
			StreamType: "execution", StreamID: "exec-1", EventType: "ExecutionCompleted",
			Data: jsonOrFail(t, map[string]any{
				"completed_at":     completedAt,
				"output":           map[string]any{"stdout": "hi"},
				"duration_ms":      1500,
				"changed":          false,
				"compliant":        true,
				"detection_output": map[string]any{"detected": true},
			}),
		})
		require.NoError(t, err)
		assert.True(t, got.CompletedAt.Equal(time.Date(2026, 4, 4, 4, 4, 4, 0, time.UTC)))
		assert.JSONEq(t, `{"stdout":"hi"}`, string(got.Output))
		require.NotNil(t, got.DurationMs)
		assert.Equal(t, int64(1500), *got.DurationMs)
		assert.False(t, got.Changed)
		assert.True(t, got.Compliant)
		assert.JSONEq(t, `{"detected":true}`, string(got.DetectionOutput))
	})

	t.Run("defaults: changed=true, compliant=false, completed_at=event.occurred_at", func(t *testing.T) {
		occurredAt := time.Date(2026, 5, 5, 5, 5, 5, 0, time.UTC)
		got, err := projectors.ExecutionCompletedFromEvent(store.PersistedEvent{
			StreamType: "execution", StreamID: "exec-2", EventType: "ExecutionCompleted",
			OccurredAt: occurredAt,
			Data:       jsonOrFail(t, map[string]any{}),
		})
		require.NoError(t, err)
		assert.True(t, got.Changed, "changed defaults to TRUE per PL/pgSQL COALESCE")
		assert.False(t, got.Compliant, "compliant defaults to FALSE per PL/pgSQL COALESCE")
		assert.True(t, got.CompletedAt.Equal(occurredAt), "missing completed_at falls back to event.occurred_at")
	})

	t.Run("wrong stream/event_type → ErrIgnoredEvent", func(t *testing.T) {
		_, err := projectors.ExecutionCompletedFromEvent(store.PersistedEvent{
			StreamType: "user", EventType: "ExecutionCompleted",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})
}

func TestExecutionFailedFromEvent_Pure(t *testing.T) {
	t.Run("error field surfaces", func(t *testing.T) {
		got, err := projectors.ExecutionFailedFromEvent(store.PersistedEvent{
			StreamType: "execution", StreamID: "exec-1", EventType: "ExecutionFailed",
			Data: jsonOrFail(t, map[string]any{
				"error":       "command failed",
				"duration_ms": 100,
			}),
		})
		require.NoError(t, err)
		require.NotNil(t, got.Error)
		assert.Equal(t, "command failed", *got.Error)
	})

	t.Run("wrong event_type → ErrIgnoredEvent", func(t *testing.T) {
		_, err := projectors.ExecutionFailedFromEvent(store.PersistedEvent{
			StreamType: "execution", EventType: "ExecutionCompleted",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})
}

func TestExecutionTimedOutFromEvent_Pure(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		got, err := projectors.ExecutionTimedOutFromEvent(store.PersistedEvent{
			StreamType: "execution", StreamID: "exec-1", EventType: "ExecutionTimedOut",
			Data: jsonOrFail(t, map[string]any{
				"error":       "timeout exceeded",
				"duration_ms": 60000,
			}),
		})
		require.NoError(t, err)
		require.NotNil(t, got.Error)
		assert.Equal(t, "timeout exceeded", *got.Error)
	})

	t.Run("wrong stream/event_type → ErrIgnoredEvent", func(t *testing.T) {
		_, err := projectors.ExecutionTimedOutFromEvent(store.PersistedEvent{
			StreamType: "execution", EventType: "ExecutionFailed",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})
}

func TestExecutionSkippedFromEvent_Pure(t *testing.T) {
	t.Run("reason surfaces", func(t *testing.T) {
		got, err := projectors.ExecutionSkippedFromEvent(store.PersistedEvent{
			StreamType: "execution", StreamID: "exec-1", EventType: "ExecutionSkipped",
			Data: jsonOrFail(t, map[string]any{"reason": "outside maintenance window"}),
		})
		require.NoError(t, err)
		require.NotNil(t, got.Reason)
		assert.Equal(t, "outside maintenance window", *got.Reason)
	})

	t.Run("wrong stream/event_type → ErrIgnoredEvent", func(t *testing.T) {
		_, err := projectors.ExecutionSkippedFromEvent(store.PersistedEvent{
			StreamType: "user", EventType: "ExecutionSkipped",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})
}

func TestExecutionCancelledFromEvent_Pure(t *testing.T) {
	t.Run("reason surfaces", func(t *testing.T) {
		got, err := projectors.ExecutionCancelledFromEvent(store.PersistedEvent{
			StreamType: "execution", StreamID: "exec-1", EventType: "ExecutionCancelled",
			Data: jsonOrFail(t, map[string]any{"reason": "operator pruned"}),
		})
		require.NoError(t, err)
		require.NotNil(t, got.Reason)
		assert.Equal(t, "operator pruned", *got.Reason)
	})

	t.Run("wrong stream/event_type → ErrIgnoredEvent", func(t *testing.T) {
		_, err := projectors.ExecutionCancelledFromEvent(store.PersistedEvent{
			StreamType: "execution", EventType: "ExecutionSkipped",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})
}

func TestExecutionStreamRefFromEvent_Pure(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		id, err := projectors.ExecutionStreamRefFromEvent(store.PersistedEvent{
			StreamType: "execution", StreamID: "exec-1", EventType: "ExecutionDispatched",
		}, "ExecutionDispatched")
		require.NoError(t, err)
		assert.Equal(t, "exec-1", id)
	})

	t.Run("wrong event_type → ErrIgnoredEvent", func(t *testing.T) {
		_, err := projectors.ExecutionStreamRefFromEvent(store.PersistedEvent{
			StreamType: "execution", EventType: "ExecutionStarted",
		}, "ExecutionDispatched")
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})
}

// ============================================================================
// Integration tests against a real Postgres testcontainer.
// ============================================================================

// TestExecutionListener_CreateDispatchStartCompleteLifecycle drives the
// canonical happy-path Create → Dispatched → Started → Completed
// sequence and asserts the projection ends in the right state at each
// step. Confirms every UPDATE handler is wired correctly.
func TestExecutionListener_CreateDispatchStartCompleteLifecycle(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	execID := testutil.NewID()

	// Created → status='pending'.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "execution", StreamID: execID, EventType: "ExecutionCreated",
		Data: map[string]any{
			"device_id":       "dev-1",
			"action_id":       "act-1",
			"action_type":     5,
			"desired_state":   1,
			"timeout_seconds": 90,
		},
		ActorType: "user", ActorID: "u-1",
	}))
	got, err := st.Queries().GetExecutionByID(ctx, execID)
	require.NoError(t, err)
	assert.Equal(t, "pending", got.Status)
	assert.Equal(t, "dev-1", got.DeviceID)
	require.NotNil(t, got.ActionID)
	assert.Equal(t, "act-1", *got.ActionID)
	assert.Equal(t, int32(5), got.ActionType)
	assert.Equal(t, int32(1), got.DesiredState)
	assert.Equal(t, int32(90), got.TimeoutSeconds)
	assert.Greater(t, got.ProjectionVersion, int64(0))

	// Dispatched → status='dispatched', dispatched_at set.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "execution", StreamID: execID, EventType: "ExecutionDispatched",
		Data: map[string]any{}, ActorType: "system", ActorID: "system",
	}))
	got, err = st.Queries().GetExecutionByID(ctx, execID)
	require.NoError(t, err)
	assert.Equal(t, "dispatched", got.Status)
	require.NotNil(t, got.DispatchedAt, "dispatched_at must be populated")

	// Started → status='running', started_at set.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "execution", StreamID: execID, EventType: "ExecutionStarted",
		Data: map[string]any{}, ActorType: "system", ActorID: "system",
	}))
	got, err = st.Queries().GetExecutionByID(ctx, execID)
	require.NoError(t, err)
	assert.Equal(t, "running", got.Status)
	require.NotNil(t, got.StartedAt)

	// Completed → status='success', terminal payload.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "execution", StreamID: execID, EventType: "ExecutionCompleted",
		Data: map[string]any{
			"output":      map[string]any{"stdout": "ok"},
			"duration_ms": 1234,
			"changed":     true,
			"compliant":   true,
		},
		ActorType: "system", ActorID: "system",
	}))
	got, err = st.Queries().GetExecutionByID(ctx, execID)
	require.NoError(t, err)
	assert.Equal(t, "success", got.Status)
	assert.JSONEq(t, `{"stdout":"ok"}`, string(got.Output))
	require.NotNil(t, got.DurationMs)
	assert.Equal(t, int64(1234), *got.DurationMs)
	assert.True(t, got.Changed)
	assert.True(t, got.Compliant)
	require.NotNil(t, got.CompletedAt)
}

// TestExecutionListener_ScheduledLifecycle drives the deferred-dispatch
// path: Scheduled → Dispatched → Started → Completed. Confirms the
// scheduled_for column is populated on the initial INSERT.
func TestExecutionListener_ScheduledLifecycle(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	execID := testutil.NewID()
	scheduledFor := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "execution", StreamID: execID, EventType: "ExecutionScheduled",
		Data: map[string]any{
			"device_id":     "dev-1",
			"action_id":     "act-1",
			"action_type":   2,
			"scheduled_for": scheduledFor.Format(time.RFC3339Nano),
		},
		ActorType: "user", ActorID: "u-1",
	}))
	got, err := st.Queries().GetExecutionByID(ctx, execID)
	require.NoError(t, err)
	assert.Equal(t, "scheduled", got.Status)
	require.NotNil(t, got.ScheduledFor)
	assert.True(t, got.ScheduledFor.Equal(scheduledFor))
}

// TestExecutionListener_TerminalStates exercises the Failed / TimedOut
// / Skipped / Cancelled paths from a Created baseline. Each is a
// separate execution row so the test stays declarative.
func TestExecutionListener_TerminalStates(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	mkPending := func(t *testing.T) string {
		t.Helper()
		id := testutil.NewID()
		require.NoError(t, st.AppendEvent(ctx, store.Event{
			StreamType: "execution", StreamID: id, EventType: "ExecutionCreated",
			Data: map[string]any{
				"device_id": "dev-1", "action_id": "act-1", "action_type": 1,
			},
			ActorType: "user", ActorID: "u",
		}))
		return id
	}

	t.Run("Failed", func(t *testing.T) {
		id := mkPending(t)
		require.NoError(t, st.AppendEvent(ctx, store.Event{
			StreamType: "execution", StreamID: id, EventType: "ExecutionFailed",
			Data: map[string]any{
				"error": "boom", "duration_ms": 50,
			},
			ActorType: "system", ActorID: "system",
		}))
		got, err := st.Queries().GetExecutionByID(ctx, id)
		require.NoError(t, err)
		assert.Equal(t, "failed", got.Status)
		require.NotNil(t, got.Error)
		assert.Equal(t, "boom", *got.Error)
	})

	t.Run("TimedOut", func(t *testing.T) {
		id := mkPending(t)
		require.NoError(t, st.AppendEvent(ctx, store.Event{
			StreamType: "execution", StreamID: id, EventType: "ExecutionTimedOut",
			Data:      map[string]any{"error": "exceeded 300s", "duration_ms": 300000},
			ActorType: "system", ActorID: "system",
		}))
		got, err := st.Queries().GetExecutionByID(ctx, id)
		require.NoError(t, err)
		assert.Equal(t, "timeout", got.Status)
		require.NotNil(t, got.Error)
		assert.Equal(t, "exceeded 300s", *got.Error)
	})

	t.Run("Skipped", func(t *testing.T) {
		id := mkPending(t)
		require.NoError(t, st.AppendEvent(ctx, store.Event{
			StreamType: "execution", StreamID: id, EventType: "ExecutionSkipped",
			Data:      map[string]any{"reason": "outside maintenance window"},
			ActorType: "system", ActorID: "system",
		}))
		got, err := st.Queries().GetExecutionByID(ctx, id)
		require.NoError(t, err)
		assert.Equal(t, "skipped", got.Status)
		require.NotNil(t, got.Error)
		assert.Equal(t, "outside maintenance window", *got.Error)
	})

	t.Run("Cancelled flips a pending row", func(t *testing.T) {
		id := mkPending(t)
		require.NoError(t, st.AppendEvent(ctx, store.Event{
			StreamType: "execution", StreamID: id, EventType: "ExecutionCancelled",
			Data:      map[string]any{"reason": "operator"},
			ActorType: "user", ActorID: "u",
		}))
		got, err := st.Queries().GetExecutionByID(ctx, id)
		require.NoError(t, err)
		assert.Equal(t, "cancelled", got.Status)
	})

	t.Run("Cancelled is a no-op once row already left scheduled/pending", func(t *testing.T) {
		id := mkPending(t)
		// Move row to running.
		require.NoError(t, st.AppendEvent(ctx, store.Event{
			StreamType: "execution", StreamID: id, EventType: "ExecutionDispatched",
			Data: map[string]any{}, ActorType: "system", ActorID: "system",
		}))
		require.NoError(t, st.AppendEvent(ctx, store.Event{
			StreamType: "execution", StreamID: id, EventType: "ExecutionStarted",
			Data: map[string]any{}, ActorType: "system", ActorID: "system",
		}))
		// Cancel arriving after dispatch is a documented no-op.
		require.NoError(t, st.AppendEvent(ctx, store.Event{
			StreamType: "execution", StreamID: id, EventType: "ExecutionCancelled",
			Data:      map[string]any{"reason": "too late"},
			ActorType: "user", ActorID: "u",
		}))
		got, err := st.Queries().GetExecutionByID(ctx, id)
		require.NoError(t, err)
		assert.Equal(t, "running", got.Status, "cancel after dispatch must NOT overwrite a real outcome")
	})
}

// TestExecutionListener_StaleReplayRejected is the asymmetric-guard
// regression lock for terminal-status reordering. An older Completed
// replayed AFTER a newer Failed must NOT flip status back to success
// — the projection_version SQL guard rejects the stale UPDATE and the
// listener's n == 0 short-circuit means no observable side effect.
//
// Without the guard, the reconciler replaying execution history out
// of order (or a duplicate event from the agent's offline scheduler)
// would rewind a row's terminal status. The PL/pgSQL projector
// stamped projection_version without a guard so this hazard was
// silent in production until #136 closed it.
func TestExecutionListener_StaleReplayRejected(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	execID := testutil.NewID()

	// Land Created.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "execution", StreamID: execID, EventType: "ExecutionCreated",
		Data: map[string]any{
			"device_id": "dev-1", "action_id": "act-1", "action_type": 1,
		},
		ActorType: "user", ActorID: "u",
	}))
	// Land Failed (the "newer" terminal state).
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "execution", StreamID: execID, EventType: "ExecutionFailed",
		Data:      map[string]any{"error": "real failure"},
		ActorType: "system", ActorID: "system",
	}))
	current, err := st.Queries().GetExecutionByID(ctx, execID)
	require.NoError(t, err)
	require.Equal(t, "failed", current.Status)
	currentVersion := current.ProjectionVersion

	// Drive the REAL listener with a synthetic Completed event whose
	// SequenceNum is OLDER than the row's current projection_version.
	// Calling the public projector entrypoint exercises both the SQL
	// guard and the listener-side n == 0 short-circuit — duplicating
	// the SQL inline would have left the branch untested even if the
	// guard was deleted.
	older := currentVersion - 5
	listener := projectors.ExecutionListener(st, slog.Default())
	listener(ctx, store.PersistedEvent{
		ID:          uuid.New(),
		SequenceNum: &older,
		StreamType:  "execution",
		StreamID:    execID,
		EventType:   "ExecutionCompleted",
		Data:        jsonOrFail(t, map[string]any{"output": map[string]any{"stdout": "stale"}}),
		ActorType:   "system",
		ActorID:     "system",
		OccurredAt:  current.CreatedAt.Add(-time.Hour),
	})

	after, err := st.Queries().GetExecutionByID(ctx, execID)
	require.NoError(t, err)
	assert.Equal(t, "failed", after.Status, "stale Completed replay must NOT flip terminal status back")
	assert.Equal(t, currentVersion, after.ProjectionVersion, "projection_version must not regress")
}

// TestExecutionListener_IgnoresWrongStreamType — defensive. Events on
// other stream types must not touch executions_projection.
func TestExecutionListener_IgnoresWrongStreamType(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	roleID := testutil.NewID()

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "role", StreamID: roleID, EventType: "ExecutionCompleted",
		Data:      map[string]any{},
		ActorType: "user", ActorID: "u",
	}))

	_, err := st.Queries().GetExecutionByID(ctx, roleID)
	require.Error(t, err, "no executions_projection row should exist for a role-stream event")
}

// TestExecutionScheduledFromEvent_TimeParseEdgeCases hardens the
// scheduled_for parsing path. The decoder rejects malformed RFC3339
// strings explicitly so a bad event surfaces as a wrapped error
// instead of silently round-tripping a zero time.Time into the
// projection (which would race with the dispatch-window guard and
// land the row in 'scheduled' state with executed_at=epoch).
func TestExecutionScheduledFromEvent_TimeParseEdgeCases(t *testing.T) {
	t.Run("RFC3339 without sub-second precision is accepted", func(t *testing.T) {
		got, err := projectors.ExecutionScheduledFromEvent(store.PersistedEvent{
			StreamType: "execution", StreamID: "exec-1", EventType: "ExecutionScheduled",
			ActorType: "user", ActorID: "u-1",
			Data: jsonOrFail(t, map[string]any{
				"device_id":     "dev-1",
				"action_type":   1,
				"scheduled_for": "2026-03-01T00:00:00Z",
			}),
		})
		require.NoError(t, err, "RFC3339Nano parser accepts plain RFC3339")
		assert.True(t, got.ScheduledFor.Equal(time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)))
	})

	t.Run("malformed scheduled_for is a wrapped error, not ErrIgnoredEvent", func(t *testing.T) {
		_, err := projectors.ExecutionScheduledFromEvent(store.PersistedEvent{
			StreamType: "execution", StreamID: "exec-2", EventType: "ExecutionScheduled",
			ActorType: "user", ActorID: "u-1",
			Data: jsonOrFail(t, map[string]any{
				"device_id":     "dev-1",
				"action_type":   1,
				"scheduled_for": "not-a-timestamp",
			}),
		})
		require.Error(t, err)
		assert.False(t, errors.Is(err, projectors.ErrIgnoredEvent),
			"a bad timestamp must surface as a validation error, not a silent skip")
		assert.Contains(t, err.Error(), "scheduled_for")
	})

	t.Run("Z and +00:00 round-trip identically", func(t *testing.T) {
		gotZ, errZ := projectors.ExecutionScheduledFromEvent(store.PersistedEvent{
			StreamType: "execution", StreamID: "exec-z", EventType: "ExecutionScheduled",
			ActorType: "user", ActorID: "u",
			Data: jsonOrFail(t, map[string]any{
				"device_id":     "dev-1",
				"action_type":   1,
				"scheduled_for": "2026-03-01T12:34:56Z",
			}),
		})
		require.NoError(t, errZ)
		gotOffset, errOffset := projectors.ExecutionScheduledFromEvent(store.PersistedEvent{
			StreamType: "execution", StreamID: "exec-o", EventType: "ExecutionScheduled",
			ActorType: "user", ActorID: "u",
			Data: jsonOrFail(t, map[string]any{
				"device_id":     "dev-1",
				"action_type":   1,
				"scheduled_for": "2026-03-01T12:34:56+00:00",
			}),
		})
		require.NoError(t, errOffset)
		assert.True(t, gotZ.ScheduledFor.Equal(gotOffset.ScheduledFor),
			"Z and +00:00 must parse to the same instant")
	})
}

// TestExecutionCreatedFromEvent_ActionIDCoalesce hardens the
// COALESCE(action_id, definition_id) semantics. The PL/pgSQL projector
// wrote action_id when present, definition_id when action_id was
// missing — used by the compliance-policy bootstrap path that
// synthesises an action row from a definition. The decoder must
// match: explicit action_id wins, missing action_id falls through to
// definition_id, neither present yields nil so the projector writes
// NULL.
func TestExecutionCreatedFromEvent_ActionIDCoalesce(t *testing.T) {
	mkEvent := func(payload map[string]any) store.PersistedEvent {
		base := map[string]any{
			"device_id":   "dev-1",
			"action_type": 1,
		}
		for k, v := range payload {
			base[k] = v
		}
		return store.PersistedEvent{
			StreamType: "execution", StreamID: "exec-x", EventType: "ExecutionCreated",
			ActorType: "user", ActorID: "u",
			Data: jsonOrFail(t, base),
		}
	}

	t.Run("action_id present wins over definition_id", func(t *testing.T) {
		got, err := projectors.ExecutionCreatedFromEvent(mkEvent(map[string]any{
			"action_id":     "act-canonical",
			"definition_id": "def-fallback",
		}))
		require.NoError(t, err)
		require.NotNil(t, got.ActionID)
		assert.Equal(t, "act-canonical", *got.ActionID)
	})

	t.Run("definition_id used when action_id absent", func(t *testing.T) {
		got, err := projectors.ExecutionCreatedFromEvent(mkEvent(map[string]any{
			"definition_id": "def-only",
		}))
		require.NoError(t, err)
		require.NotNil(t, got.ActionID)
		assert.Equal(t, "def-only", *got.ActionID,
			"COALESCE(action_id, definition_id) falls back to definition_id")
	})

	t.Run("neither action_id nor definition_id → ActionID nil (NULL in projection)", func(t *testing.T) {
		got, err := projectors.ExecutionCreatedFromEvent(mkEvent(map[string]any{}))
		require.NoError(t, err)
		assert.Nil(t, got.ActionID,
			"both action_id and definition_id absent must yield nil so the listener writes NULL")
	})

	t.Run("empty-string action_id falls through to definition_id", func(t *testing.T) {
		got, err := projectors.ExecutionCreatedFromEvent(mkEvent(map[string]any{
			"action_id":     "",
			"definition_id": "def-via-empty",
		}))
		require.NoError(t, err)
		require.NotNil(t, got.ActionID)
		assert.Equal(t, "def-via-empty", *got.ActionID,
			"empty-string action_id collapses to nil, then COALESCE falls back to definition_id")
	})
}
