package postgres

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/store/generated"
)

// OSQuery implements store.OSQueryRepo against osquery_results.
type OSQuery struct {
	q *generated.Queries
}

// NewOSQuery returns an OSQuery repo bound to the given sqlc handle.
func NewOSQuery(q *generated.Queries) *OSQuery {
	return &OSQuery{q: q}
}

func (o *OSQuery) CreateResult(ctx context.Context, queryID, deviceID, tableName string) error {
	if err := o.q.CreateOSQueryResult(ctx, generated.CreateOSQueryResultParams{
		QueryID:   queryID,
		DeviceID:  deviceID,
		TableName: tableName,
	}); err != nil {
		return fmt.Errorf("osquery: create result: %w", err)
	}
	return nil
}

func (o *OSQuery) GetResult(ctx context.Context, queryID string) (store.OSQueryResult, error) {
	row, err := o.q.GetOSQueryResult(ctx, queryID)
	if err != nil {
		return store.OSQueryResult{}, fmt.Errorf("osquery: get result: %w", translateNotFound(err))
	}
	return store.OSQueryResult{
		QueryID:     row.QueryID,
		DeviceID:    row.DeviceID,
		TableName:   row.TableName,
		Completed:   row.Completed,
		Success:     row.Success,
		Error:       row.Error,
		Rows:        json.RawMessage(row.Rows),
		CreatedAt:   row.CreatedAt,
		CompletedAt: row.CompletedAt,
	}, nil
}

func (o *OSQuery) ExpirePendingResult(ctx context.Context, queryID, errMsg string) error {
	if err := o.q.ExpirePendingOSQueryResult(ctx, generated.ExpirePendingOSQueryResultParams{
		QueryID: queryID,
		Error:   errMsg,
	}); err != nil {
		return fmt.Errorf("osquery: expire pending: %w", err)
	}
	return nil
}
