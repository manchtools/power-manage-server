package postgres

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/store/generated"
)

// Definition implements store.DefinitionRepo against
// definitions_projection + definition_members_projection.
type Definition struct {
	q *generated.Queries
}

// NewDefinition returns a Definition repo bound to the given sqlc
// handle.
func NewDefinition(q *generated.Queries) *Definition {
	return &Definition{q: q}
}

func (d *Definition) Get(ctx context.Context, id string) (store.Definition, error) {
	row, err := d.q.GetDefinitionByID(ctx, id)
	if err != nil {
		return store.Definition{}, fmt.Errorf("definition: get: %w", translateNotFound(err))
	}
	return definitionFromRow(row), nil
}

func (d *Definition) List(ctx context.Context, filter store.ListDefinitionsFilter) ([]store.Definition, error) {
	rows, err := d.q.ListDefinitions(ctx, generated.ListDefinitionsParams{
		Limit:  filter.Limit,
		Offset: filter.Offset,
	})
	if err != nil {
		return nil, fmt.Errorf("definition: list: %w", err)
	}
	out := make([]store.Definition, len(rows))
	for i, r := range rows {
		out[i] = definitionFromRow(r)
	}
	return out, nil
}

func (d *Definition) Count(ctx context.Context) (int64, error) {
	n, err := d.q.CountDefinitions(ctx)
	if err != nil {
		return 0, fmt.Errorf("definition: count: %w", translateNotFound(err))
	}
	return n, nil
}

func (d *Definition) ListMembers(ctx context.Context, definitionID string) ([]store.DefinitionMember, error) {
	rows, err := d.q.ListDefinitionMembers(ctx, definitionID)
	if err != nil {
		return nil, fmt.Errorf("definition: list members: %w", err)
	}
	out := make([]store.DefinitionMember, len(rows))
	for i, r := range rows {
		out[i] = store.DefinitionMember{
			DefinitionID:  r.DefinitionID,
			ActionSetID:   r.ActionSetID,
			SortOrder:     r.SortOrder,
			AddedAt:       r.AddedAt,
			ActionSetName: r.ActionSetName,
		}
	}
	return out, nil
}

func definitionFromRow(r generated.DefinitionsProjection) store.Definition {
	return store.Definition{
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
