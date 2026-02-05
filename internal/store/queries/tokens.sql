-- name: GetTokenByID :one
SELECT * FROM tokens_projection
WHERE id = $1 AND is_deleted = FALSE;

-- name: GetTokenByHash :one
SELECT * FROM tokens_projection
WHERE value_hash = $1 AND is_deleted = FALSE;

-- name: ListTokens :many
SELECT * FROM tokens_projection
WHERE is_deleted = FALSE
  AND ($1::BOOLEAN OR disabled = FALSE)
ORDER BY created_at DESC
LIMIT $2 OFFSET $3;

-- name: CountTokens :one
SELECT COUNT(*) FROM tokens_projection
WHERE is_deleted = FALSE
  AND ($1::BOOLEAN OR disabled = FALSE);

-- name: ListActiveTokens :many
SELECT * FROM tokens_projection
WHERE is_deleted = FALSE
  AND disabled = FALSE
  AND (expires_at IS NULL OR expires_at > NOW())
ORDER BY created_at DESC;

-- name: ListTokensByOwner :many
SELECT * FROM tokens_projection
WHERE is_deleted = FALSE
  AND owner_id = $1
  AND ($2::BOOLEAN OR disabled = FALSE)
ORDER BY created_at DESC
LIMIT $3 OFFSET $4;

-- name: CountTokensByOwner :one
SELECT COUNT(*) FROM tokens_projection
WHERE is_deleted = FALSE
  AND owner_id = $1
  AND ($2::BOOLEAN OR disabled = FALSE);

-- name: GetValidToken :one
-- Validates a token for device registration
SELECT * FROM tokens_projection
WHERE value_hash = $1
  AND is_deleted = FALSE
  AND disabled = FALSE
  AND (expires_at IS NULL OR expires_at > NOW())
  AND (max_uses = 0 OR current_uses < max_uses);
