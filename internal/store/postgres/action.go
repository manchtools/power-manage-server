package postgres

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/store/generated"
)

// Action implements store.ActionRepo against actions_projection.
type Action struct {
	q *generated.Queries
}

// NewAction returns an Action repo bound to the given sqlc handle.
func NewAction(q *generated.Queries) *Action {
	return &Action{q: q}
}

func (a *Action) Get(ctx context.Context, id string) (store.Action, error) {
	row, err := a.q.GetActionByID(ctx, id)
	if err != nil {
		return store.Action{}, fmt.Errorf("action: get: %w", translateNotFound(err))
	}
	return actionFromRow(row), nil
}

func (a *Action) List(ctx context.Context, filter store.ListActionsFilter) ([]store.Action, error) {
	rows, err := a.q.ListActions(ctx, generated.ListActionsParams{
		Column1:        filter.ActionTypeFilter,
		Limit:          filter.Limit,
		Offset:         filter.Offset,
		UnassignedOnly: filter.UnassignedOnly,
	})
	if err != nil {
		return nil, fmt.Errorf("action: list: %w", err)
	}
	out := make([]store.Action, len(rows))
	for i, r := range rows {
		out[i] = actionFromRow(r)
	}
	return out, nil
}

func (a *Action) Count(ctx context.Context, filter store.CountActionsFilter) (int64, error) {
	n, err := a.q.CountActions(ctx, generated.CountActionsParams{
		Column1:        filter.ActionTypeFilter,
		UnassignedOnly: filter.UnassignedOnly,
	})
	if err != nil {
		return 0, fmt.Errorf("action: count: %w", translateNotFound(err))
	}
	return n, nil
}

func (a *Action) NamesByIDs(ctx context.Context, ids []string) ([]store.ActionNamePair, error) {
	rows, err := a.q.GetActionNamesByIDs(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("action: names by ids: %w", err)
	}
	out := make([]store.ActionNamePair, len(rows))
	for i, r := range rows {
		out[i] = store.ActionNamePair{ID: r.ID, Name: r.Name}
	}
	return out, nil
}

func (a *Action) UpdateSignature(ctx context.Context, p store.UpdateActionSignatureParams) error {
	if err := a.q.UpdateActionSignature(ctx, generated.UpdateActionSignatureParams{
		ID:              p.ID,
		Signature:       p.Signature,
		ParamsCanonical: []byte(p.ParamsCanonical),
	}); err != nil {
		return fmt.Errorf("action: update signature: %w", err)
	}
	return nil
}

func actionFromRow(r generated.ActionsProjection) store.Action {
	return store.Action{
		ID:              r.ID,
		Name:            r.Name,
		Description:     r.Description,
		ActionType:      r.ActionType,
		Params:          json.RawMessage(r.Params),
		TimeoutSeconds:  r.TimeoutSeconds,
		CreatedAt:       r.CreatedAt,
		CreatedBy:       r.CreatedBy,
		Signature:       r.Signature,
		ParamsCanonical: json.RawMessage(r.ParamsCanonical),
		DesiredState:    r.DesiredState,
		IsSystem:        r.IsSystem,
		UpdatedAt:       r.UpdatedAt,
		Schedule:        json.RawMessage(r.Schedule),
	}
}
