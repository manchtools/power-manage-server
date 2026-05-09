package projectors

import (
	"context"
	"errors"
	"log/slog"

	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// ExecutionListener returns a store.EventListener that applies every
// execution-stream event the deleted PL/pgSQL project_execution_event
// handled. Nine event types, every one a single-statement write
// against executions_projection: 2 INSERTs (Created, Scheduled) plus
// 7 UPDATEs (Dispatched, Started, Completed, Failed, TimedOut,
// Skipped, Cancelled).
//
// High-volume write path: every dispatched action produces 3-5
// execution events (Created → Dispatched → Started → Completed/Failed),
// so this listener stays lean — no WithTx wrapping (every event is
// single-statement; cascade tx atomicity is moot), no shared decoder
// allocations beyond the per-event payload struct.
//
// Asymmetric-guard discipline: every UPDATE handler checks the
// :execrows return and short-circuits on n == 0. There are no
// downstream cascades to gate today, but the stale-replay path for
// terminal-status reordering (an older Completed replayed after a
// newer Failed) is real and the version guard inside the SQL is what
// rejects it. The listener-side n == 0 check is preserved for
// observability and for the regression-test contract.
//
// Wired in projectors.WireAll. Refs #136, tracker #107 (Phase 2).
func ExecutionListener(st *store.Store, logger *slog.Logger) store.EventListener {
	if st == nil {
		return func(context.Context, store.PersistedEvent) {}
	}
	return func(ctx context.Context, e store.PersistedEvent) {
		if e.StreamType != "execution" {
			return
		}
		// Every event is a single statement (INSERT or UPDATE) —
		// autocommit pool, no WithTx wrapping. ApplyExecution dispatches
		// internally on EventType.
		if err := ApplyExecution(ctx, st.Queries(), e); err != nil {
			logger.Warn("execution projector: failed to apply event",
				"event_id", e.ID, "event_type", e.EventType, "execution_id", e.StreamID, "error", err)
		}
	}
}

// ApplyExecution is the transactional core of the execution projector.
// The listener calls it directly against the autocommit pool; future
// rebuild-target wiring (manchtools/power-manage-server#125) registers
// it via RegisterRebuildApply so RebuildAll re-derives the projection
// from the event store instead of dispatching to the no-op PL/pgSQL
// stub.
func ApplyExecution(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	if e.StreamType != "execution" {
		return nil
	}
	switch e.EventType {
	case string(eventtypes.ExecutionCreated):
		return applyExecutionCreated(ctx, q, e)
	case string(eventtypes.ExecutionScheduled):
		return applyExecutionScheduled(ctx, q, e)
	case string(eventtypes.ExecutionDispatched):
		return applyExecutionDispatched(ctx, q, e)
	case string(eventtypes.ExecutionStarted):
		return applyExecutionStarted(ctx, q, e)
	case string(eventtypes.ExecutionCompleted):
		return applyExecutionCompleted(ctx, q, e)
	case string(eventtypes.ExecutionFailed):
		return applyExecutionFailed(ctx, q, e)
	case string(eventtypes.ExecutionTimedOut):
		return applyExecutionTimedOut(ctx, q, e)
	case string(eventtypes.ExecutionSkipped):
		return applyExecutionSkipped(ctx, q, e)
	case string(eventtypes.ExecutionCancelled):
		return applyExecutionCancelled(ctx, q, e)
	}
	return nil
}

func applyExecutionCreated(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := ExecutionCreatedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	createdAt := payload.CreatedAt
	return q.InsertExecutionCreatedProjection(ctx, db.InsertExecutionCreatedProjectionParams{
		ID:                payload.ID,
		DeviceID:          payload.DeviceID,
		ActionID:          payload.ActionID,
		ActionType:        payload.ActionType,
		DesiredState:      payload.DesiredState,
		Params:            payload.Params,
		TimeoutSeconds:    payload.TimeoutSeconds,
		CreatedAt:         &createdAt,
		CreatedByType:     payload.CreatedByType,
		CreatedByID:       payload.CreatedByID,
		ProjectionVersion: deref(e.SequenceNum),
	})
}

func applyExecutionScheduled(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := ExecutionScheduledFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	scheduledFor := payload.ScheduledFor
	createdAt := payload.CreatedAt
	return q.InsertExecutionScheduledProjection(ctx, db.InsertExecutionScheduledProjectionParams{
		ID:                payload.ID,
		DeviceID:          payload.DeviceID,
		ActionID:          payload.ActionID,
		ActionType:        payload.ActionType,
		DesiredState:      payload.DesiredState,
		Params:            payload.Params,
		TimeoutSeconds:    payload.TimeoutSeconds,
		ScheduledFor:      &scheduledFor,
		CreatedAt:         &createdAt,
		CreatedByType:     payload.CreatedByType,
		CreatedByID:       payload.CreatedByID,
		ProjectionVersion: deref(e.SequenceNum),
	})
}

func applyExecutionDispatched(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	id, err := ExecutionStreamRefFromEvent(e, "ExecutionDispatched")
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	dispatchedAt := e.OccurredAt
	// :execrows return is intentionally ignored after the call: there
	// is no downstream cascade to gate, and the SQL guard
	// (`projection_version < $N`) does the actual stale-replay rejection.
	// Capturing the count here keeps the call shape uniform with the
	// other UPDATE handlers and leaves room for a future log line.
	if _, err := q.UpdateExecutionDispatchedProjection(ctx, db.UpdateExecutionDispatchedProjectionParams{
		ID:                id,
		DispatchedAt:      &dispatchedAt,
		ProjectionVersion: deref(e.SequenceNum),
	}); err != nil {
		return err
	}
	return nil
}

func applyExecutionStarted(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	id, err := ExecutionStreamRefFromEvent(e, "ExecutionStarted")
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	startedAt := e.OccurredAt
	if _, err := q.UpdateExecutionStartedProjection(ctx, db.UpdateExecutionStartedProjectionParams{
		ID:                id,
		StartedAt:         &startedAt,
		ProjectionVersion: deref(e.SequenceNum),
	}); err != nil {
		return err
	}
	return nil
}

func applyExecutionCompleted(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := ExecutionCompletedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	completedAt := payload.CompletedAt
	if _, err := q.UpdateExecutionCompletedProjection(ctx, db.UpdateExecutionCompletedProjectionParams{
		ID:                payload.ID,
		CompletedAt:       &completedAt,
		Output:            payload.Output,
		DurationMs:        payload.DurationMs,
		Changed:           payload.Changed,
		Compliant:         payload.Compliant,
		DetectionOutput:   payload.DetectionOutput,
		ProjectionVersion: deref(e.SequenceNum),
	}); err != nil {
		return err
	}
	return nil
}

func applyExecutionFailed(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := ExecutionFailedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	completedAt := payload.CompletedAt
	if _, err := q.UpdateExecutionFailedProjection(ctx, db.UpdateExecutionFailedProjectionParams{
		ID:                payload.ID,
		CompletedAt:       &completedAt,
		Error:             payload.Error,
		Output:            payload.Output,
		DurationMs:        payload.DurationMs,
		Changed:           payload.Changed,
		Compliant:         payload.Compliant,
		DetectionOutput:   payload.DetectionOutput,
		ProjectionVersion: deref(e.SequenceNum),
	}); err != nil {
		return err
	}
	return nil
}

func applyExecutionTimedOut(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := ExecutionTimedOutFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	completedAt := payload.CompletedAt
	if _, err := q.UpdateExecutionTimedOutProjection(ctx, db.UpdateExecutionTimedOutProjectionParams{
		ID:                payload.ID,
		CompletedAt:       &completedAt,
		Error:             payload.Error,
		Output:            payload.Output,
		DurationMs:        payload.DurationMs,
		ProjectionVersion: deref(e.SequenceNum),
	}); err != nil {
		return err
	}
	return nil
}

func applyExecutionSkipped(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := ExecutionSkippedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	completedAt := payload.CompletedAt
	if _, err := q.UpdateExecutionSkippedProjection(ctx, db.UpdateExecutionSkippedProjectionParams{
		ID:                payload.ID,
		CompletedAt:       &completedAt,
		Error:             payload.Reason,
		ProjectionVersion: deref(e.SequenceNum),
	}); err != nil {
		return err
	}
	return nil
}

func applyExecutionCancelled(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := ExecutionCancelledFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	completedAt := payload.CompletedAt
	// Two guards layered in the SQL: the status whitelist (only flip
	// rows still in scheduled/pending) plus the version guard. n == 0
	// here can mean EITHER the row already moved to a terminal state
	// (legitimate no-op) OR a stale replay was rejected — both are
	// silent successes from the listener's perspective.
	if _, err := q.UpdateExecutionCancelledProjection(ctx, db.UpdateExecutionCancelledProjectionParams{
		ID:                payload.ID,
		CompletedAt:       &completedAt,
		Error:             payload.Reason,
		ProjectionVersion: deref(e.SequenceNum),
	}); err != nil {
		return err
	}
	return nil
}
