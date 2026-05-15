package postgres

import (
	"context"
	"fmt"

	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/store/generated"
)

// AuthState implements store.AuthStateRepo against auth_states.
type AuthState struct {
	q *generated.Queries
}

// NewAuthState returns an AuthState repo bound to the given sqlc handle.
func NewAuthState(q *generated.Queries) *AuthState {
	return &AuthState{q: q}
}

func (a *AuthState) Create(ctx context.Context, params store.CreateAuthStateParams) error {
	if err := a.q.CreateAuthState(ctx, generated.CreateAuthStateParams{
		State:        params.State,
		ProviderID:   params.ProviderID,
		Nonce:        params.Nonce,
		CodeVerifier: params.CodeVerifier,
		RedirectUri:  params.RedirectURI,
		ExpiresAt:    params.ExpiresAt,
	}); err != nil {
		return fmt.Errorf("auth_state: create: %w", err)
	}
	return nil
}

func (a *AuthState) Consume(ctx context.Context, state string) (store.AuthState, error) {
	row, err := a.q.ConsumeAuthState(ctx, state)
	if err != nil {
		return store.AuthState{}, fmt.Errorf("auth_state: consume: %w", translateNotFound(err))
	}
	return store.AuthState{
		State:        row.State,
		ProviderID:   row.ProviderID,
		Nonce:        row.Nonce,
		CodeVerifier: row.CodeVerifier,
		RedirectURI:  row.RedirectUri,
		CreatedAt:    row.CreatedAt,
		ExpiresAt:    row.ExpiresAt,
	}, nil
}
