package store

import (
	"context"
	"encoding/json"
	"time"
)

// OSQueryResult is the on-demand osquery result row. Backed by
// osquery_results (not by the event store), so the shape can evolve
// without event-schema implications — same posture as
// LogQueryResult.
type OSQueryResult struct {
	QueryID   string
	DeviceID  string
	TableName string
	Completed bool
	Success   bool
	Error     string
	// Rows is the raw JSON payload returned by osquery's structured
	// table output. Kept as json.RawMessage at the boundary so each
	// backend chooses how to materialize the column without leaking
	// the choice to handlers.
	Rows        json.RawMessage
	CreatedAt   time.Time
	CompletedAt *time.Time
}

// OSQueryRepo manages the on-demand osquery result rows used by the
// DispatchOSQuery / GetOSQueryResult RPC pair. The agent writes the
// completed result via the gateway inbox path; this repo covers the
// creation, expiry, and read sites the control handler owns.
type OSQueryRepo interface {
	// CreateResult inserts a fresh pending row for the given
	// query+device+table triple. Called when the control handler
	// dispatches an osquery to the agent.
	CreateResult(ctx context.Context, queryID, deviceID, tableName string) error

	// GetResult returns the row for the given query ID. Returns
	// ErrNotFound when no such row exists.
	GetResult(ctx context.Context, queryID string) (OSQueryResult, error)

	// ExpirePendingResult marks a pending row as failed with the
	// supplied error message. Used by the auto-expiry path
	// (5-minute poll timeout) and by the dispatch-failure recovery.
	ExpirePendingResult(ctx context.Context, queryID, errMsg string) error
}
