package store

import (
	"context"
	"encoding/json"
	"time"
)

// Execution is the per-action-dispatch result row from
// executions_projection. ActionID is *string because an execution
// can be agent-scheduled (no API-side action row) or compliance-only
// (action_id NULL after the action row is deleted). Params /
// Output / DetectionOutput stay as opaque JSON at the boundary.
type Execution struct {
	ID              string
	DeviceID        string
	ActionID        *string
	ActionType      int32
	DesiredState    int32
	Params          json.RawMessage
	TimeoutSeconds  int32
	Status          string
	Error           *string
	Output          json.RawMessage
	CreatedAt       *time.Time
	DispatchedAt    *time.Time
	StartedAt       *time.Time
	CompletedAt     *time.Time
	DurationMs      *int64
	CreatedByType   string
	CreatedByID     string
	Changed         bool
	Compliant       bool
	DetectionOutput json.RawMessage
	ScheduledFor    *time.Time
}

// StaleExecution is the narrow shape returned by ListStale — the
// stale-expiry sweep only needs the fields necessary to emit the
// timeout event.
type StaleExecution struct {
	ID             string
	DeviceID       string
	TimeoutSeconds int32
	Status         string
	CreatedAt      *time.Time
	DispatchedAt   *time.Time
}

// ListExecutionsFilter pairs pagination with the four filter axes
// the UI exposes. Empty / zero values disable each filter
// independently — the projection-side query treats "" / 0 as "no
// filter on this axis".
type ListExecutionsFilter struct {
	DeviceID         string
	Status           string
	ActionTypeFilter int32
	Search           string
	Limit            int32
	Offset           int32
}

// CountExecutionsFilter mirrors ListExecutionsFilter's filter
// fields. Both shapes must stay in sync so pagination totals line
// up with the rows actually returned.
type CountExecutionsFilter struct {
	DeviceID         string
	Status           string
	ActionTypeFilter int32
	Search           string
}

// WarmFilter is the narrow pagination shape used by the search
// warm-up sweep (no filters — just window-by-age cap + page).
type WarmFilter struct {
	Limit  int32
	Offset int32
}

// ExecutionRepo reads execution state. Writes flow through events
// (ExecutionCreated / Dispatched / Started / Completed / etc.) and
// the projector listener.
type ExecutionRepo interface {
	// Get returns an execution by ID. Returns ErrNotFound when no
	// execution with that ID exists.
	Get(ctx context.Context, id string) (Execution, error)

	// List returns a page of executions matching the filter, ordered
	// by created_at descending.
	List(ctx context.Context, filter ListExecutionsFilter) ([]Execution, error)

	// Count returns the total matching the filter.
	Count(ctx context.Context, filter CountExecutionsFilter) (int64, error)

	// ListPendingForDevice returns 'pending' + 'dispatched'
	// executions for a device, oldest first. Used by the
	// reconnect-dispatch flow to re-send executions whose agent was
	// offline.
	ListPendingForDevice(ctx context.Context, deviceID string) ([]Execution, error)

	// ListStale returns dispatched executions that have exceeded
	// timeout + grace. The periodic expiry sweep uses this to emit
	// ExecutionTimedOut events.
	ListStale(ctx context.Context) ([]StaleExecution, error)

	// ListForWarm returns recent (≤90d) executions for the search
	// warm-up sweep.
	ListForWarm(ctx context.Context, filter WarmFilter) ([]Execution, error)

	// CountForWarm returns the total recent-execution count for the
	// warm-up pagination.
	CountForWarm(ctx context.Context) (int64, error)

	// LoadOutputChunks loads every ExecutionOutputChunk event for
	// the given execution stream ID, ordered by sequence. The
	// chunks are stored on the event stream rather than as
	// projection rows, hence the cross-shape (returns
	// PersistedEvent rather than execution data).
	LoadOutputChunks(ctx context.Context, executionID string) ([]PersistedEvent, error)
}
