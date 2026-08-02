-- name: RevokeToken :one
INSERT INTO revoked_tokens (jti, expires_at) VALUES (?, ?) ON CONFLICT (jti) DO NOTHING
RETURNING jti;

-- name: IsTokenRevoked :one
SELECT EXISTS(SELECT 1 FROM revoked_tokens WHERE jti = ?);

-- name: CleanupExpiredRevocations :execrows
DELETE FROM revoked_tokens WHERE expires_at < sqlc.arg(expired_before);
