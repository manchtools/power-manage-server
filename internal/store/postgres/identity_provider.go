package postgres

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/store/generated"
)

// IdentityProvider implements store.IdentityProviderRepo against
// identity_providers_projection.
type IdentityProvider struct {
	q *generated.Queries
}

// NewIdentityProvider returns an IdentityProvider repo bound to the
// given sqlc handle.
func NewIdentityProvider(q *generated.Queries) *IdentityProvider {
	return &IdentityProvider{q: q}
}

func (i *IdentityProvider) Get(ctx context.Context, id string) (store.IdentityProvider, error) {
	row, err := i.q.GetIdentityProviderByID(ctx, id)
	if err != nil {
		return store.IdentityProvider{}, fmt.Errorf("identity_provider: get: %w", translateNotFound(err))
	}
	return identityProviderFromRow(row), nil
}

func (i *IdentityProvider) GetBySlug(ctx context.Context, slug string) (store.IdentityProvider, error) {
	row, err := i.q.GetIdentityProviderBySlug(ctx, slug)
	if err != nil {
		return store.IdentityProvider{}, fmt.Errorf("identity_provider: get by slug: %w", translateNotFound(err))
	}
	return identityProviderFromRow(row), nil
}

func (i *IdentityProvider) GetBySlugForSCIM(ctx context.Context, slug string) (store.IdentityProvider, error) {
	row, err := i.q.GetIdentityProviderBySlugForSCIM(ctx, slug)
	if err != nil {
		return store.IdentityProvider{}, fmt.Errorf("identity_provider: get by slug for scim: %w", translateNotFound(err))
	}
	return identityProviderFromRow(row), nil
}

func (i *IdentityProvider) List(ctx context.Context, filter store.ListIdentityProvidersFilter) ([]store.IdentityProvider, error) {
	rows, err := i.q.ListIdentityProviders(ctx, generated.ListIdentityProvidersParams{
		Limit:  filter.Limit,
		Offset: filter.Offset,
	})
	if err != nil {
		return nil, fmt.Errorf("identity_provider: list: %w", err)
	}
	out := make([]store.IdentityProvider, len(rows))
	for j, r := range rows {
		out[j] = identityProviderFromRow(r)
	}
	return out, nil
}

func (i *IdentityProvider) Count(ctx context.Context) (int64, error) {
	n, err := i.q.CountIdentityProviders(ctx)
	if err != nil {
		return 0, fmt.Errorf("identity_provider: count: %w", translateNotFound(err))
	}
	return n, nil
}

func (i *IdentityProvider) ListEnabled(ctx context.Context) ([]store.IdentityProvider, error) {
	rows, err := i.q.ListEnabledIdentityProviders(ctx)
	if err != nil {
		return nil, fmt.Errorf("identity_provider: list enabled: %w", err)
	}
	out := make([]store.IdentityProvider, len(rows))
	for j, r := range rows {
		out[j] = identityProviderFromRow(r)
	}
	return out, nil
}

// identityProviderFromRow translates a sqlc projection row to the
// domain shape. Shared so the field mapping lives in one place.
func identityProviderFromRow(r generated.IdentityProvidersProjection) store.IdentityProvider {
	return store.IdentityProvider{
		ID:                       r.ID,
		Name:                     r.Name,
		Slug:                     r.Slug,
		ProviderType:             r.ProviderType,
		Enabled:                  r.Enabled,
		ClientID:                 r.ClientID,
		ClientSecretEncrypted:    r.ClientSecretEncrypted,
		IssuerURL:                r.IssuerUrl,
		AuthorizationURL:         r.AuthorizationUrl,
		TokenURL:                 r.TokenUrl,
		UserinfoURL:              r.UserinfoUrl,
		Scopes:                   r.Scopes,
		AutoCreateUsers:          r.AutoCreateUsers,
		AutoLinkByEmail:          r.AutoLinkByEmail,
		DefaultRoleID:            r.DefaultRoleID,
		AttributeMapping:         json.RawMessage(r.AttributeMapping),
		DisablePasswordForLinked: r.DisablePasswordForLinked,
		GroupClaim:               r.GroupClaim,
		GroupMapping:             json.RawMessage(r.GroupMapping),
		CreatedAt:                r.CreatedAt,
		CreatedBy:                r.CreatedBy,
		UpdatedAt:                r.UpdatedAt,
		ScimEnabled:              r.ScimEnabled,
		ScimTokenHash:            r.ScimTokenHash,
	}
}
