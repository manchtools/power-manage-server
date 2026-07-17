package postgres

import (
	"context"
	"fmt"

	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/store/generated"
)

// Token implements store.TokenRepo against tokens_projection.
type Token struct {
	q *generated.Queries
}

// NewToken returns a Token repo bound to the given sqlc handle.
func NewToken(q *generated.Queries) *Token {
	return &Token{q: q}
}

func (t *Token) Get(ctx context.Context, id string, ownerScope *string) (store.Token, error) {
	row, err := t.q.GetTokenByID(ctx, generated.GetTokenByIDParams{
		ID:            id,
		FilterOwnerID: ownerScope,
	})
	if err != nil {
		return store.Token{}, fmt.Errorf("token: get: %w", translateNotFound(err))
	}
	return tokenFromRow(row), nil
}

func (t *Token) GetByHash(ctx context.Context, valueHash string) (store.Token, error) {
	row, err := t.q.GetTokenByHash(ctx, valueHash)
	if err != nil {
		return store.Token{}, fmt.Errorf("token: get by hash: %w", translateNotFound(err))
	}
	return tokenFromRow(row), nil
}

func (t *Token) List(ctx context.Context, filter store.ListTokensFilter) ([]store.Token, error) {
	rows, err := t.q.ListTokens(ctx, generated.ListTokensParams{
		Column1:       filter.IncludeDisabled,
		Limit:         filter.Limit,
		Offset:        filter.Offset,
		FilterOwnerID: filter.OwnerScope,
	})
	if err != nil {
		return nil, fmt.Errorf("token: list: %w", err)
	}
	out := make([]store.Token, len(rows))
	for i, row := range rows {
		out[i] = tokenFromRow(row)
	}
	return out, nil
}

func (t *Token) Count(ctx context.Context, filter store.CountTokensFilter) (int64, error) {
	n, err := t.q.CountTokens(ctx, generated.CountTokensParams{
		Column1:       filter.IncludeDisabled,
		FilterOwnerID: filter.OwnerScope,
	})
	if err != nil {
		return 0, fmt.Errorf("token: count: %w", translateNotFound(err))
	}
	return n, nil
}

// tokenFromRow translates a sqlc projection row to the domain shape.
// Shared by Get / GetByHash / List so the field mapping lives in
// one place.
func tokenFromRow(row generated.TokensProjection) store.Token {
	return store.Token{
		ID:                row.ID,
		ValueHash:         row.ValueHash,
		Name:              row.Name,
		OneTime:           row.OneTime,
		MaxUses:           row.MaxUses,
		CurrentUses:       row.CurrentUses,
		ExpiresAt:         row.ExpiresAt,
		CreatedAt:         row.CreatedAt,
		CreatedBy:         row.CreatedBy,
		Disabled:          row.Disabled,
		OwnerID:           row.OwnerID,
		ProjectionVersion: row.ProjectionVersion,
	}
}
