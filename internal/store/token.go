package store

import (
	"context"
	"time"
)

// Token is a registration-token row from tokens_projection. Used for
// agent enrollment + one-time / multi-use scoped issuance. JWT
// refresh-token revocations are a separate table — see RevokedTokenRepo.
type Token struct {
	ID          string
	ValueHash   string
	Name        string
	OneTime     bool
	MaxUses     int32
	CurrentUses int32
	ExpiresAt   *time.Time
	CreatedAt   *time.Time
	CreatedBy   string
	Disabled    bool
	OwnerID     *string
}

// ListTokensFilter is the pagination + scoping shape for ListTokens.
//
// OwnerScope == nil → no owner scoping (admin view, all tokens).
// OwnerScope != nil → restrict to tokens whose owner_id matches —
//
//	used by the `:self`-scoped variant of the list permission so
//	users only see their own tokens.
type ListTokensFilter struct {
	IncludeDisabled bool
	OwnerScope      *string
	Limit           int32
	Offset          int32
}

// CountTokensFilter mirrors ListTokensFilter for the count side; the
// filter shape must stay identical so pagination totals line up with
// what ListTokens actually returns.
type CountTokensFilter struct {
	IncludeDisabled bool
	OwnerScope      *string
}

// TokenRepo reads + manages the registration-token projection. Writes
// flow through the event store (TokenCreated, TokenDisabled,
// TokenDeleted, TokenUsed), not through this interface.
type TokenRepo interface {
	// Get returns a token by ID. ownerScope, when non-nil, restricts
	// the lookup to tokens owned by that user — yields ErrNotFound
	// instead of a permission error when the owner doesn't match,
	// preserving the existing handler behaviour. nil = no scope.
	Get(ctx context.Context, id string, ownerScope *string) (Token, error)

	// GetByHash looks up a token by its value hash. Used by the
	// registration handler when an agent presents a token; the
	// projection's UNIQUE(value_hash) guarantees at most one row.
	GetByHash(ctx context.Context, valueHash string) (Token, error)

	// List returns a page of tokens matching the filter. Empty slice
	// past the end.
	List(ctx context.Context, filter ListTokensFilter) ([]Token, error)

	// Count returns the total matching the filter. Pair with List
	// for paginated UIs.
	Count(ctx context.Context, filter CountTokensFilter) (int64, error)
}
