package postgres

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/store/generated"
)

// ActionSet implements store.ActionSetRepo against
// action_sets_projection + action_set_members_projection.
type ActionSet struct {
	q *generated.Queries
}

// NewActionSet returns an ActionSet repo bound to the given sqlc
// handle.
func NewActionSet(q *generated.Queries) *ActionSet {
	return &ActionSet{q: q}
}

func (s *ActionSet) Get(ctx context.Context, id string) (store.ActionSet, error) {
	row, err := s.q.GetActionSetByID(ctx, id)
	if err != nil {
		return store.ActionSet{}, fmt.Errorf("action_set: get: %w", translateNotFound(err))
	}
	return actionSetFromRow(row), nil
}

func (s *ActionSet) List(ctx context.Context, filter store.ListActionSetsFilter) ([]store.ActionSet, error) {
	rows, err := s.q.ListActionSets(ctx, generated.ListActionSetsParams{
		Limit:          filter.Limit,
		Offset:         filter.Offset,
		UnassignedOnly: filter.UnassignedOnly,
	})
	if err != nil {
		return nil, fmt.Errorf("action_set: list: %w", err)
	}
	out := make([]store.ActionSet, len(rows))
	for i, r := range rows {
		out[i] = actionSetFromRow(r)
	}
	return out, nil
}

func (s *ActionSet) Count(ctx context.Context, unassignedOnly bool) (int64, error) {
	n, err := s.q.CountActionSets(ctx, unassignedOnly)
	if err != nil {
		return 0, fmt.Errorf("action_set: count: %w", translateNotFound(err))
	}
	return n, nil
}

func (s *ActionSet) ListMembers(ctx context.Context, setID string) ([]store.ActionSetMember, error) {
	rows, err := s.q.ListActionSetMembers(ctx, setID)
	if err != nil {
		return nil, fmt.Errorf("action_set: list members: %w", err)
	}
	out := make([]store.ActionSetMember, len(rows))
	for i, r := range rows {
		out[i] = store.ActionSetMember{
			SetID:      r.SetID,
			ActionID:   r.ActionID,
			SortOrder:  r.SortOrder,
			AddedAt:    r.AddedAt,
			ActionName: r.ActionName,
			ActionType: r.ActionType,
		}
	}
	return out, nil
}

func (s *ActionSet) ListInDefinition(ctx context.Context, definitionID string) ([]store.ActionSet, error) {
	rows, err := s.q.ListActionSetsInDefinition(ctx, definitionID)
	if err != nil {
		return nil, fmt.Errorf("action_set: list in definition: %w", err)
	}
	out := make([]store.ActionSet, len(rows))
	for i, r := range rows {
		out[i] = actionSetFromRow(r)
	}
	return out, nil
}

func actionSetFromRow(r generated.ActionSetsProjection) store.ActionSet {
	return store.ActionSet{
		ID:          r.ID,
		Name:        r.Name,
		Description: r.Description,
		MemberCount: r.MemberCount,
		CreatedAt:   r.CreatedAt,
		CreatedBy:   r.CreatedBy,
		UpdatedAt:   r.UpdatedAt,
		Schedule:    json.RawMessage(r.Schedule),
	}
}
