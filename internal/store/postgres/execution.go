package postgres

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/store/generated"
)

// Execution implements store.ExecutionRepo against
// executions_projection (and reaches into the event store for
// LoadOutputChunks).
type Execution struct {
	q *generated.Queries
}

// NewExecution returns an Execution repo bound to the given sqlc
// handle.
func NewExecution(q *generated.Queries) *Execution {
	return &Execution{q: q}
}

func (e *Execution) Get(ctx context.Context, id string) (store.Execution, error) {
	row, err := e.q.GetExecutionByID(ctx, id)
	if err != nil {
		return store.Execution{}, fmt.Errorf("execution: get: %w", translateNotFound(err))
	}
	return executionFromRow(row), nil
}

func (e *Execution) List(ctx context.Context, filter store.ListExecutionsFilter) ([]store.Execution, error) {
	rows, err := e.q.ListExecutions(ctx, generated.ListExecutionsParams{
		Column1: filter.DeviceID,
		Column2: filter.Status,
		Column3: filter.ActionTypeFilter,
		Column4: filter.Search,
		Limit:   filter.Limit,
		Offset:  filter.Offset,
	})
	if err != nil {
		return nil, fmt.Errorf("execution: list: %w", err)
	}
	out := make([]store.Execution, len(rows))
	for i, r := range rows {
		out[i] = executionFromRow(r)
	}
	return out, nil
}

func (e *Execution) Count(ctx context.Context, filter store.CountExecutionsFilter) (int64, error) {
	n, err := e.q.CountExecutions(ctx, generated.CountExecutionsParams{
		Column1: filter.DeviceID,
		Column2: filter.Status,
		Column3: filter.ActionTypeFilter,
		Column4: filter.Search,
	})
	if err != nil {
		return 0, fmt.Errorf("execution: count: %w", translateNotFound(err))
	}
	return n, nil
}

func (e *Execution) ListPendingForDevice(ctx context.Context, deviceID string) ([]store.Execution, error) {
	rows, err := e.q.ListPendingExecutionsForDevice(ctx, deviceID)
	if err != nil {
		return nil, fmt.Errorf("execution: list pending for device: %w", err)
	}
	out := make([]store.Execution, len(rows))
	for i, r := range rows {
		out[i] = executionFromRow(r)
	}
	return out, nil
}

func (e *Execution) ListStale(ctx context.Context) ([]store.StaleExecution, error) {
	rows, err := e.q.ListStaleExecutions(ctx)
	if err != nil {
		return nil, fmt.Errorf("execution: list stale: %w", err)
	}
	out := make([]store.StaleExecution, len(rows))
	for i, r := range rows {
		out[i] = store.StaleExecution{
			ID:             r.ID,
			DeviceID:       r.DeviceID,
			TimeoutSeconds: r.TimeoutSeconds,
			Status:         r.Status,
			CreatedAt:      r.CreatedAt,
			DispatchedAt:   r.DispatchedAt,
		}
	}
	return out, nil
}

func (e *Execution) ListForWarm(ctx context.Context, filter store.WarmFilter) ([]store.Execution, error) {
	rows, err := e.q.ListExecutionsForWarm(ctx, generated.ListExecutionsForWarmParams{
		Limit:  filter.Limit,
		Offset: filter.Offset,
	})
	if err != nil {
		return nil, fmt.Errorf("execution: list for warm: %w", err)
	}
	out := make([]store.Execution, len(rows))
	for i, r := range rows {
		out[i] = executionFromRow(r)
	}
	return out, nil
}

func (e *Execution) CountForWarm(ctx context.Context) (int64, error) {
	n, err := e.q.CountExecutionsForWarm(ctx)
	if err != nil {
		return 0, fmt.Errorf("execution: count for warm: %w", translateNotFound(err))
	}
	return n, nil
}

func (e *Execution) LoadOutputChunks(ctx context.Context, executionID string) ([]store.PersistedEvent, error) {
	rows, err := e.q.LoadOutputChunks(ctx, executionID)
	if err != nil {
		return nil, fmt.Errorf("execution: load output chunks: %w", err)
	}
	return rows, nil
}

func executionFromRow(r generated.ExecutionsProjection) store.Execution {
	return store.Execution{
		ID:              r.ID,
		DeviceID:        r.DeviceID,
		ActionID:        r.ActionID,
		ActionType:      r.ActionType,
		DesiredState:    r.DesiredState,
		Params:          json.RawMessage(r.Params),
		TimeoutSeconds:  r.TimeoutSeconds,
		Status:          r.Status,
		Error:           r.Error,
		Output:          json.RawMessage(r.Output),
		CreatedAt:       r.CreatedAt,
		DispatchedAt:    r.DispatchedAt,
		StartedAt:       r.StartedAt,
		CompletedAt:     r.CompletedAt,
		DurationMs:      r.DurationMs,
		CreatedByType:   r.CreatedByType,
		CreatedByID:     r.CreatedByID,
		Changed:         r.Changed,
		Compliant:       r.Compliant,
		DetectionOutput: json.RawMessage(r.DetectionOutput),
		ScheduledFor:    r.ScheduledFor,
	}
}
