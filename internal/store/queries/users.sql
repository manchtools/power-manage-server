-- name: GetUserByID :one
SELECT * FROM users_projection
WHERE id = $1 AND is_deleted = FALSE;

-- name: GetUserByEmail :one
SELECT * FROM users_projection
WHERE email = $1 AND is_deleted = FALSE;

-- name: ListUsers :many
SELECT * FROM users_projection
WHERE is_deleted = FALSE
ORDER BY created_at DESC
LIMIT $1 OFFSET $2;

-- name: CountUsers :one
SELECT COUNT(*) FROM users_projection
WHERE is_deleted = FALSE;

-- name: ListAllUsers :many
SELECT * FROM users_projection
ORDER BY created_at DESC
LIMIT $1 OFFSET $2;

-- name: GetUserSessionInfo :one
SELECT disabled, session_version, is_deleted FROM users_projection
WHERE id = $1;
