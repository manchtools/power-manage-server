-- Registration-token CRUD. The reserved host bootstrap token is deliberately
-- absent from this surface: it has its own consume-once boundary.

-- name: GetRegistrationToken :one
SELECT * FROM tokens
WHERE id = sqlc.arg(id)
  AND is_deleted = FALSE
  AND name <> sqlc.arg(reserved_name);

-- name: ListRegistrationTokens :many
SELECT * FROM tokens
WHERE is_deleted = FALSE
  AND name <> sqlc.arg(reserved_name)
  AND id > sqlc.arg(after_id)
  AND (sqlc.arg(include_disabled) OR disabled = FALSE)
ORDER BY id
LIMIT sqlc.arg(row_limit);

-- name: CountRegistrationTokens :one
SELECT COUNT(*) FROM tokens
WHERE is_deleted = FALSE
  AND name <> sqlc.arg(reserved_name)
  AND (sqlc.arg(include_disabled) OR disabled = FALSE);

-- name: InsertRegistrationToken :one
INSERT INTO tokens (
    id, value_hash, name, one_time, max_uses, current_uses,
    expires_at, created_at, created_by, owner_id, disabled, is_deleted
) VALUES (
    sqlc.arg(id), sqlc.arg(value_hash), sqlc.arg(name), sqlc.arg(one_time),
    sqlc.arg(max_uses), 0, sqlc.narg(expires_at), sqlc.arg(created_at),
    sqlc.arg(created_by), sqlc.narg(owner_id), FALSE, FALSE
)
RETURNING *;

-- Consume one enrollment use atomically. The bearer digest is the only lookup
-- key and all usability predicates live in this UPDATE, so concurrent callers
-- cannot both consume the final use.
-- name: ConsumeRegistrationToken :one
UPDATE tokens
SET current_uses = current_uses + 1
WHERE value_hash = sqlc.arg(value_hash)
  AND is_deleted = FALSE
  AND disabled = FALSE
  AND name <> sqlc.arg(reserved_name)
  AND (expires_at IS NULL OR expires_at > sqlc.arg(consumed_at))
  AND (
      (one_time = TRUE AND current_uses = 0)
      OR
      (one_time = FALSE AND (max_uses = 0 OR current_uses < max_uses))
  )
RETURNING *;

-- name: RenameRegistrationToken :one
UPDATE tokens
SET name = sqlc.arg(name)
WHERE id = sqlc.arg(id)
  AND is_deleted = FALSE
  AND name <> sqlc.arg(reserved_name)
RETURNING *;

-- name: SetRegistrationTokenDisabled :one
UPDATE tokens
SET disabled = sqlc.arg(disabled)
WHERE id = sqlc.arg(id)
  AND is_deleted = FALSE
  AND name <> sqlc.arg(reserved_name)
RETURNING *;

-- name: SoftDeleteRegistrationToken :one
UPDATE tokens
SET is_deleted = TRUE
WHERE id = sqlc.arg(id)
  AND is_deleted = FALSE
  AND name <> sqlc.arg(reserved_name)
RETURNING *;
