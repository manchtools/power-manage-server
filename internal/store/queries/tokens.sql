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

-- name: InsertTokenProjection :exec
-- TokenCreated handler. ON CONFLICT DO NOTHING for replay safety —
-- the reconciler may re-deliver the event; if a row already exists
-- under the same id, leave it alone. Composite-key partials
-- (TokenRenamed/Used/etc) own subsequent mutations.
INSERT INTO tokens_projection (
    id, value_hash, name, one_time, max_uses, expires_at,
    created_at, created_by, owner_id, projection_version
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
ON CONFLICT (id) DO NOTHING;

-- name: RenameTokenProjection :exec
-- TokenRenamed handler. projection_version guard rejects stale
-- reconciler replays.
UPDATE tokens_projection
SET name              = $2,
    projection_version = $3
WHERE id = $1
  AND projection_version < $3;

-- name: IncrementTokenUseProjection :exec
-- TokenUsed handler. Uses current_uses + 1 (matches PL/pgSQL); a
-- duplicate event from the reconciler would erroneously bump the
-- counter twice without the projection_version guard, so the guard
-- is load-bearing here, not just defensive.
UPDATE tokens_projection
SET current_uses      = current_uses + 1,
    projection_version = $2
WHERE id = $1
  AND projection_version < $2;

-- name: SetTokenDisabledProjection :exec
-- TokenDisabled / TokenEnabled handler — same shape, parameterised
-- on the disabled bool. Listener picks the bool per event_type.
UPDATE tokens_projection
SET disabled          = $2,
    projection_version = $3
WHERE id = $1
  AND projection_version < $3;

-- name: SoftDeleteTokenProjection :exec
-- TokenDeleted handler. Marks the row deleted; row stays so audit
-- queries can resolve token names by id.
UPDATE tokens_projection
SET is_deleted        = TRUE,
    projection_version = $2
WHERE id = $1
  AND projection_version < $2;
