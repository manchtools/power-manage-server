package postgres

import (
	"context"
	"fmt"

	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/store/generated"
)

// Assignment implements store.AssignmentRepo against
// assignments_projection.
type Assignment struct {
	q *generated.Queries
}

// NewAssignment returns an Assignment repo bound to the given sqlc
// handle.
func NewAssignment(q *generated.Queries) *Assignment {
	return &Assignment{q: q}
}

func (a *Assignment) Get(ctx context.Context, key store.AssignmentKey) (store.Assignment, error) {
	row, err := a.q.GetAssignment(ctx, generated.GetAssignmentParams{
		SourceType: key.SourceType,
		SourceID:   key.SourceID,
		TargetType: key.TargetType,
		TargetID:   key.TargetID,
	})
	if err != nil {
		return store.Assignment{}, fmt.Errorf("assignment: get: %w", translateNotFound(err))
	}
	return assignmentFromRow(row), nil
}

func (a *Assignment) GetByID(ctx context.Context, id string) (store.Assignment, error) {
	row, err := a.q.GetAssignmentByID(ctx, id)
	if err != nil {
		return store.Assignment{}, fmt.Errorf("assignment: get by id: %w", translateNotFound(err))
	}
	return assignmentFromRow(row), nil
}

func (a *Assignment) List(ctx context.Context, filter store.ListAssignmentsFilter) ([]store.AssignmentWithNames, error) {
	rows, err := a.q.ListAssignments(ctx, generated.ListAssignmentsParams{
		Column1: filter.SourceType,
		Column2: filter.SourceID,
		Column3: filter.TargetType,
		Column4: filter.TargetID,
		Limit:   filter.Limit,
		Offset:  filter.Offset,
	})
	if err != nil {
		return nil, fmt.Errorf("assignment: list: %w", err)
	}
	out := make([]store.AssignmentWithNames, len(rows))
	for i, r := range rows {
		out[i] = store.AssignmentWithNames{
			Assignment: store.Assignment{
				ID:         r.ID,
				SourceType: r.SourceType,
				SourceID:   r.SourceID,
				TargetType: r.TargetType,
				TargetID:   r.TargetID,
				SortOrder:  r.SortOrder,
				Mode:       r.Mode,
				CreatedAt:  r.CreatedAt,
				CreatedBy:  r.CreatedBy,
			},
			SourceName: r.SourceName,
			TargetName: r.TargetName,
		}
	}
	return out, nil
}

func (a *Assignment) Count(ctx context.Context, filter store.CountAssignmentsFilter) (int64, error) {
	n, err := a.q.CountAssignments(ctx, generated.CountAssignmentsParams{
		Column1: filter.SourceType,
		Column2: filter.SourceID,
		Column3: filter.TargetType,
		Column4: filter.TargetID,
	})
	if err != nil {
		return 0, fmt.Errorf("assignment: count: %w", translateNotFound(err))
	}
	return n, nil
}

func (a *Assignment) ListAvailableForDevice(ctx context.Context, deviceID string) ([]store.Assignment, error) {
	rows, err := a.q.ListAvailableAssignmentsForDevice(ctx, deviceID)
	if err != nil {
		return nil, fmt.Errorf("assignment: list available for device: %w", err)
	}
	out := make([]store.Assignment, len(rows))
	for i, r := range rows {
		out[i] = assignmentFromRow(r)
	}
	return out, nil
}

func (a *Assignment) ListAssignedUserIDsForDevice(ctx context.Context, deviceID string) ([]string, error) {
	ids, err := a.q.ListDeviceAssignedUserIDs(ctx, deviceID)
	if err != nil {
		return nil, fmt.Errorf("assignment: list assigned user ids for device: %w", err)
	}
	return ids, nil
}

func assignmentFromRow(r generated.AssignmentsProjection) store.Assignment {
	return store.Assignment{
		ID:         r.ID,
		SourceType: r.SourceType,
		SourceID:   r.SourceID,
		TargetType: r.TargetType,
		TargetID:   r.TargetID,
		SortOrder:  r.SortOrder,
		Mode:       r.Mode,
		CreatedAt:  r.CreatedAt,
		CreatedBy:  r.CreatedBy,
	}
}
