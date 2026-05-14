package postgres

import (
	"context"
	"fmt"

	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/store/generated"
)

// IdentityLink implements store.IdentityLinkRepo against the
// identity_links_projection via sqlc-generated queries.
type IdentityLink struct {
	q *generated.Queries
}

// NewIdentityLink returns an IdentityLink repo bound to the given
// sqlc handle.
func NewIdentityLink(q *generated.Queries) *IdentityLink {
	return &IdentityLink{q: q}
}

// Get returns a single identity link by its ID. pgx.ErrNoRows is
// translated to store.ErrNotFound.
func (i *IdentityLink) Get(ctx context.Context, id string) (store.IdentityLink, error) {
	row, err := i.q.GetIdentityLinkByID(ctx, id)
	if err != nil {
		return store.IdentityLink{}, fmt.Errorf("identity_link: get: %w", translateNotFound(err))
	}
	return store.IdentityLink{
		ID:            row.ID,
		UserID:        row.UserID,
		ProviderID:    row.ProviderID,
		ExternalID:    row.ExternalID,
		ExternalEmail: row.ExternalEmail,
		ExternalName:  row.ExternalName,
		LinkedAt:      row.LinkedAt,
		LastLoginAt:   row.LastLoginAt,
	}, nil
}

// ListForUser returns the user's links joined with provider display
// fields. The underlying :many query returns an empty slice (not an
// error) when the user has no links.
func (i *IdentityLink) ListForUser(ctx context.Context, userID string) ([]store.IdentityLinkWithProvider, error) {
	rows, err := i.q.ListIdentityLinksForUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("identity_link: list for user: %w", err)
	}
	out := make([]store.IdentityLinkWithProvider, len(rows))
	for j, r := range rows {
		out[j] = store.IdentityLinkWithProvider{
			IdentityLink: store.IdentityLink{
				ID:            r.ID,
				UserID:        r.UserID,
				ProviderID:    r.ProviderID,
				ExternalID:    r.ExternalID,
				ExternalEmail: r.ExternalEmail,
				ExternalName:  r.ExternalName,
				LinkedAt:      r.LinkedAt,
				LastLoginAt:   r.LastLoginAt,
			},
			ProviderName: r.ProviderName,
			ProviderSlug: r.ProviderSlug,
		}
	}
	return out, nil
}

// CountForUser returns the number of identity links the user owns.
// The COUNT(*) :one query always returns a row, so the
// pgx.ErrNoRows path is unreachable today — the translateNotFound
// wrap stays as future-proofing if the query shape ever changes.
func (i *IdentityLink) CountForUser(ctx context.Context, userID string) (int64, error) {
	n, err := i.q.CountIdentityLinksForUser(ctx, userID)
	if err != nil {
		return 0, fmt.Errorf("identity_link: count for user: %w", translateNotFound(err))
	}
	return n, nil
}
