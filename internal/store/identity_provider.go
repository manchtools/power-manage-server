package store

import (
	"context"
	"encoding/json"
	"time"
)

// IdentityProvider is the per-provider OIDC/SSO configuration row.
// ClientSecretEncrypted stays encrypted at the boundary; the handler
// decrypts via internal/crypto when initiating the OIDC dance.
//
// ScimTokenHash is the bcrypt hash of the SCIM bearer token —
// surfaced here because the SCIM auth handler validates incoming
// bearer tokens against this column. Treat with the same care as
// ClientSecretEncrypted (don't log; don't return to clients).
type IdentityProvider struct {
	ID                    string
	Name                  string
	Slug                  string
	ProviderType          string
	Enabled               bool
	ClientID              string
	ClientSecretEncrypted string
	IssuerURL             string
	AuthorizationURL      string
	TokenURL              string
	UserinfoURL           string
	Scopes                []string
	AutoCreateUsers       bool
	AutoLinkByEmail       bool
	// TrustEmailAssertions: when true, the operator has knowingly delegated
	// email-identity assertion to this IdP, so SCIM AutoLinkByEmail may bind an
	// asserted email to a pre-existing LOCAL PASSWORD account. Default false —
	// without it, auto-link to a password account is refused (account-takeover
	// guard). See WS5 #2 / migration 012.
	TrustEmailAssertions     bool
	DefaultRoleID            string
	AttributeMapping         json.RawMessage
	DisablePasswordForLinked bool
	GroupClaim               string
	GroupMapping             json.RawMessage
	CreatedAt                time.Time
	CreatedBy                string
	UpdatedAt                time.Time
	ScimEnabled              bool
	ScimTokenHash            string
}

// ListIdentityProvidersFilter is the pagination shape for the
// provider list endpoint.
type ListIdentityProvidersFilter struct {
	Limit  int32
	Offset int32
}

// IdentityProviderRepo reads the identity-provider configuration
// projection. Writes (IdentityProviderCreated / Updated / SCIMEnabled /
// SCIMTokenRotated) flow through the event store + projector — the
// projector's listener writes are NOT covered by this repo.
type IdentityProviderRepo interface {
	// Get returns the provider with the given ID. Returns ErrNotFound
	// when no such provider exists.
	Get(ctx context.Context, id string) (IdentityProvider, error)

	// GetBySlug returns the provider with the given slug. Returns
	// ErrNotFound for unknown slugs.
	GetBySlug(ctx context.Context, slug string) (IdentityProvider, error)

	// GetBySlugForSCIM returns the provider by slug, restricted to
	// SCIM-enabled providers. Returns ErrNotFound when the provider
	// is unknown OR SCIM is disabled — the SCIM auth handler maps
	// both to 401 without distinguishing.
	GetBySlugForSCIM(ctx context.Context, slug string) (IdentityProvider, error)

	// List returns a page of providers.
	List(ctx context.Context, filter ListIdentityProvidersFilter) ([]IdentityProvider, error)

	// Count returns the total number of non-deleted providers.
	Count(ctx context.Context) (int64, error)

	// ListEnabled returns every non-deleted, enabled provider. Used
	// by the login UI to populate the SSO button list.
	ListEnabled(ctx context.Context) ([]IdentityProvider, error)
}
