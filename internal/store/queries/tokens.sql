-- name: GetTokenByID :one
SELECT * FROM tokens_projection
WHERE id = $1 AND is_deleted = FALSE
  AND (sqlc.narg('filter_owner_id')::TEXT IS NULL OR owner_id = sqlc.narg('filter_owner_id'));

-- name: GetTokenByHash :one
SELECT * FROM tokens_projection
WHERE value_hash = $1 AND is_deleted = FALSE;

-- name: ListTokens :many
SELECT * FROM tokens_projection
WHERE is_deleted = FALSE
  AND ($1::BOOLEAN OR disabled = FALSE)
  AND (sqlc.narg('filter_owner_id')::TEXT IS NULL OR owner_id = sqlc.narg('filter_owner_id'))
ORDER BY created_at DESC
LIMIT $2 OFFSET $3;

-- name: CountTokens :one
SELECT COUNT(*) FROM tokens_projection
WHERE is_deleted = FALSE
  AND ($1::BOOLEAN OR disabled = FALSE)
  AND (sqlc.narg('filter_owner_id')::TEXT IS NULL OR owner_id = sqlc.narg('filter_owner_id'));

-- name: ListActiveTokens :many
SELECT * FROM tokens_projection
WHERE is_deleted = FALSE
  AND disabled = FALSE
  AND (expires_at IS NULL OR expires_at > NOW())
ORDER BY created_at DESC;

-- name: GetValidToken :one
-- Validates a token for device registration
SELECT * FROM tokens_projection
WHERE value_hash = $1
  AND is_deleted = FALSE
  AND disabled = FALSE
  AND (expires_at IS NULL OR expires_at > NOW())
  AND (max_uses = 0 OR current_uses < max_uses);
