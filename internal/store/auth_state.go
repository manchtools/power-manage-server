package store

import (
	"context"
	"time"
)

// AuthState is the per-flow OIDC/OAuth state row used to thread the
// authorization-code dance through the SSO handler. Each row pins
// the original nonce + code verifier + redirect URI for one in-flight
// login attempt; rows are consumed on first read so any replay
// surfaces as ErrNotFound.
type AuthState struct {
	State        string
	ProviderID   string
	Nonce        string
	CodeVerifier string
	RedirectURI  string
	CreatedAt    time.Time
	ExpiresAt    time.Time
}

// CreateAuthStateParams carries the fields the SSO handler stages
// when initiating a login. The state token (PKCE-bound) is the
// primary key.
type CreateAuthStateParams struct {
	State        string
	ProviderID   string
	Nonce        string
	CodeVerifier string
	RedirectURI  string
	ExpiresAt    time.Time
}

// AuthStateRepo manages short-lived SSO/OIDC authorization-state rows.
// The Consume path is destructive — the row is deleted as part of the
// read so a stolen state token can't be replayed.
type AuthStateRepo interface {
	// Create stages a fresh state row. The underlying :exec query
	// has no return shape; integrity-error surface (e.g. duplicate
	// state) bubbles up unchanged.
	Create(ctx context.Context, params CreateAuthStateParams) error

	// Consume reads-and-deletes the state row in one statement.
	// Returns ErrNotFound when the state is unknown, expired, or
	// already consumed by an earlier callback.
	Consume(ctx context.Context, state string) (AuthState, error)
}
