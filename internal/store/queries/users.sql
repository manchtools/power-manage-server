-- name: InsertUser :one
-- A user carries no authorization of its own: what the subject may do
-- comes from user_roles and user_group_roles.
INSERT INTO users (id, email, display_name, created_at, updated_at)
VALUES ($1, $2, $3, $4, $4)
RETURNING *;

-- name: GetUser :one
SELECT * FROM users WHERE id = $1 AND is_deleted = FALSE;

-- name: GetUserByEmail :one
SELECT * FROM users WHERE email = $1 AND is_deleted = FALSE;

-- name: UpdateUserEmail :execrows
UPDATE users SET email = $2, updated_at = $3 WHERE id = $1 AND is_deleted = FALSE;

-- name: SetUserDisabled :execrows
-- Disabling bumps session_version in the same statement, so every
-- session already issued to the subject stops validating at once.
UPDATE users
SET disabled = $2, session_version = session_version + 1, updated_at = $3
WHERE id = $1 AND is_deleted = FALSE AND disabled <> $2;

-- name: DeleteUser :execrows
-- Erasure of ordinary personal state. The subject's DEK is destroyed
-- separately, which is what makes the sealed audit detail unreadable.
DELETE FROM users WHERE id = $1;

-- name: CountUsers :one
SELECT COUNT(*) FROM users WHERE is_deleted = FALSE;

-- name: GetNextLinuxUID :one
SELECT nextval('linux_uid_seq')::INTEGER;
