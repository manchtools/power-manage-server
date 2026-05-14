package store

import (
	"context"
	"time"
)

// LogQueryResult is the device-log-query result row. Backed by
// log_query_results, NOT by the event store — this is a derived
// scratchpad for the async dispatch/poll dance, so the shape can
// evolve without event-schema implications.
type LogQueryResult struct {
	QueryID     string
	DeviceID    string
	Completed   bool
	Success     bool
	Error       string
	Logs        string
	CreatedAt   time.Time
	CompletedAt *time.Time
}

// LogsRepo manages the device-log-query result rows used by the
// QueryDeviceLogs / GetDeviceLogResult RPC pair. The agent writes
// the completed result via a separate gateway path; this repo
// covers the creation, expiry, and read sites the control handler
// owns.
type LogsRepo interface {
	// CreateQueryResult inserts a fresh pending row for the given
	// query+device pair. Called when the control handler dispatches
	// a log query to the agent.
	CreateQueryResult(ctx context.Context, queryID, deviceID string) error

	// GetQueryResult returns the row for the given query ID.
	// Returns ErrNotFound when no such row exists (caller used a
	// bogus query ID, or the row was already aged out by the
	// periodic cleanup).
	GetQueryResult(ctx context.Context, queryID string) (LogQueryResult, error)

	// ExpirePendingQueryResult marks a pending row as failed with
	// the supplied error message. Used by the auto-expiry path
	// (5-minute poll timeout) and by the dispatch-failure recovery
	// in QueryDeviceLogs.
	ExpirePendingQueryResult(ctx context.Context, queryID, errMsg string) error
}
