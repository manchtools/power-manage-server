package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/manchtools/power-manage/server/internal/store/generated"
)

// RevokedToken implements store.RevokedTokenRepo against the
// revoked_tokens table.
type RevokedToken struct {
	q *generated.Queries
}

// NewRevokedToken returns a RevokedToken repo bound to the given
// sqlc handle.
func NewRevokedToken(q *generated.Queries) *RevokedToken {
	return &RevokedToken{q: q}
}

func (r *RevokedToken) Revoke(ctx context.Context, jti string, expiresAt time.Time) (string, error) {
	out, err := r.q.RevokeToken(ctx, generated.RevokeTokenParams{
		Jti:       jti,
		ExpiresAt: expiresAt,
	})
	if err != nil {
		return "", fmt.Errorf("revoked_token: revoke: %w", translateNotFound(err))
	}
	return out, nil
}

func (r *RevokedToken) IsRevoked(ctx context.Context, jti string) (bool, error) {
	revoked, err := r.q.IsTokenRevoked(ctx, jti)
	if err != nil {
		return false, fmt.Errorf("revoked_token: is revoked: %w", translateNotFound(err))
	}
	return revoked, nil
}
