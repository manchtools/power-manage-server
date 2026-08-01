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
  AND (sqlc.arg(include_disabled)::boolean OR disabled = FALSE)
ORDER BY id
LIMIT sqlc.arg(row_limit);

-- name: CountRegistrationTokens :one
SELECT COUNT(*) FROM tokens
WHERE is_deleted = FALSE
  AND name <> sqlc.arg(reserved_name)
  AND (sqlc.arg(include_disabled)::boolean OR disabled = FALSE);

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
