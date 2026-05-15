package store

import (
	"context"
	"time"
)

// RevokedTokenRepo manages the JWT refresh-token revocation list. It
// is intentionally separate from TokenRepo — registration tokens
// (tokens_projection) and revoked JWTs (revoked_tokens) share only
// the word "token"; they're different tables with different
// lifecycles. The auth handler uses both, but the two domains are
// otherwise unrelated.
type RevokedTokenRepo interface {
	// Revoke inserts the jti into the revocation list with the
	// supplied TTL (the JWT's original expiry). Returns the inserted
	// jti on success; ErrNotFound when the row was already present
	// (the underlying INSERT ... ON CONFLICT DO NOTHING RETURNING
	// shape), which the caller uses to detect concurrent-revocation
	// races without surfacing them as errors.
	Revoke(ctx context.Context, jti string, expiresAt time.Time) (string, error)

	// IsRevoked reports whether the jti is on the revocation list.
	// Used in the refresh-token validation path.
	IsRevoked(ctx context.Context, jti string) (bool, error)
}
