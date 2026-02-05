-- name: RevokeToken :exec
INSERT INTO revoked_tokens (jti, expires_at) VALUES ($1, $2) ON CONFLICT (jti) DO NOTHING;

-- name: IsTokenRevoked :one
SELECT EXISTS(SELECT 1 FROM revoked_tokens WHERE jti = $1);

-- name: CleanupExpiredRevocations :exec
DELETE FROM revoked_tokens WHERE expires_at < NOW();
