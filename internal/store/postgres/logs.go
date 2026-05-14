package postgres

import (
	"context"
	"fmt"

	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/store/generated"
)

// Logs implements store.LogsRepo against log_query_results.
type Logs struct {
	q *generated.Queries
}

// NewLogs returns a Logs repo bound to the given sqlc handle.
func NewLogs(q *generated.Queries) *Logs {
	return &Logs{q: q}
}

// CreateQueryResult inserts a pending row. The underlying :exec
// query has no return value beyond errors; backend constraint
// violations (e.g. duplicate query_id) surface unchanged.
func (l *Logs) CreateQueryResult(ctx context.Context, queryID, deviceID string) error {
	if err := l.q.CreateLogQueryResult(ctx, generated.CreateLogQueryResultParams{
		QueryID:  queryID,
		DeviceID: deviceID,
	}); err != nil {
		return fmt.Errorf("logs: create query result: %w", err)
	}
	return nil
}

// GetQueryResult returns the result row. pgx.ErrNoRows is
// translated to store.ErrNotFound.
func (l *Logs) GetQueryResult(ctx context.Context, queryID string) (store.LogQueryResult, error) {
	row, err := l.q.GetLogQueryResult(ctx, queryID)
	if err != nil {
		return store.LogQueryResult{}, fmt.Errorf("logs: get query result: %w", translateNotFound(err))
	}
	return store.LogQueryResult{
		QueryID:     row.QueryID,
		DeviceID:    row.DeviceID,
		Completed:   row.Completed,
		Success:     row.Success,
		Error:       row.Error,
		Logs:        row.Logs,
		CreatedAt:   row.CreatedAt,
		CompletedAt: row.CompletedAt,
	}, nil
}

// ExpirePendingQueryResult marks a pending row as failed. The :exec
// query's WHERE clause includes `completed = FALSE` so calling on
// an already-completed row is a no-op and not an error.
func (l *Logs) ExpirePendingQueryResult(ctx context.Context, queryID, errMsg string) error {
	if err := l.q.ExpirePendingLogQueryResult(ctx, generated.ExpirePendingLogQueryResultParams{
		QueryID: queryID,
		Error:   errMsg,
	}); err != nil {
		return fmt.Errorf("logs: expire pending: %w", err)
	}
	return nil
}
