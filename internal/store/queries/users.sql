-- name: InsertUser :one
-- A user carries no authorization of its own: what the subject may do
-- comes from user_roles and user_group_roles.
INSERT INTO users (
    id, email, display_name, given_name, family_name, preferred_username,
    linux_username, linux_uid, provisioning_source, created_at, updated_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $10)
RETURNING *;

-- name: GetUser :one
SELECT * FROM users WHERE id = $1 AND is_deleted = FALSE;

-- name: GetUserByEmail :one
SELECT * FROM users WHERE email = $1 AND is_deleted = FALSE;

-- name: GetUserSessionState :one
-- Deliberately unfiltered by is_deleted: the refresh path must be able
-- to tell a retired subject from an unknown one and refuse both.
SELECT id, disabled, is_deleted, session_version FROM users WHERE id = $1;

-- name: ListUsers :many
-- Keyset pagination on the ULID primary key: ULIDs sort by mint time,
-- so ordering by id is a stable cursor a concurrent insert cannot
-- shift rows across.
SELECT * FROM users
WHERE is_deleted = FALSE AND id > $1
ORDER BY id
LIMIT $2;

-- name: UpdateUserEmail :execrows
UPDATE users SET email = $2, updated_at = $3 WHERE id = $1 AND is_deleted = FALSE;

-- name: UpdateUserProfile :one
UPDATE users
SET display_name = $2,
    given_name = $3,
    family_name = $4,
    preferred_username = $5,
    picture = $6,
    locale = $7,
    updated_at = $8
WHERE id = $1 AND is_deleted = FALSE
RETURNING *;

-- name: UpdateUserSshSettings :one
UPDATE users
SET ssh_access_enabled = $2, ssh_allow_pubkey = $3, ssh_allow_password = $4, updated_at = $5
WHERE id = $1 AND is_deleted = FALSE
RETURNING *;

-- name: UpdateUserLinuxUsername :one
UPDATE users SET linux_username = $2, updated_at = $3
WHERE id = $1 AND is_deleted = FALSE
RETURNING *;

-- name: SetUserProvisioningEnabled :one
UPDATE users SET user_provisioning_enabled = $2, updated_at = $3
WHERE id = $1 AND is_deleted = FALSE
RETURNING *;

-- name: SetUserDisabled :execrows
-- Disabling bumps session_version in the same statement, so every
-- session already issued to the subject stops validating at once.
UPDATE users
SET disabled = $2, session_version = session_version + 1, updated_at = $3
WHERE id = $1 AND is_deleted = FALSE AND disabled <> $2;

-- name: BumpUserSessionVersion :one
-- Any change to what a subject may do invalidates the sessions minted
-- under the old authority. The new value is returned so the caller can
-- record the transition as audit evidence.
UPDATE users SET session_version = session_version + 1, updated_at = $2
WHERE id = $1 AND is_deleted = FALSE
RETURNING session_version;

-- name: TouchUserLastLogin :execrows
UPDATE users SET last_login_at = $2, updated_at = $2 WHERE id = $1 AND is_deleted = FALSE;

-- name: DeleteUser :execrows
-- Erasure of ordinary personal state. The subject's DEK is destroyed
-- separately, which is what makes the sealed audit detail unreadable.
DELETE FROM users WHERE id = $1;

-- name: CountUsers :one
SELECT COUNT(*) FROM users WHERE is_deleted = FALSE;

-- name: GetNextLinuxUID :one
SELECT nextval('linux_uid_seq')::INTEGER;

-- name: GetServerSettings :one
SELECT * FROM server_settings WHERE id = '00000000000000000000000003';

-- name: UpdateServerSettings :one
UPDATE server_settings
SET user_provisioning_enabled = sqlc.arg(user_provisioning_enabled),
    ssh_access_for_all = sqlc.arg(ssh_access_for_all),
    updated_at = sqlc.arg(updated_at)
WHERE id = '00000000000000000000000003'
RETURNING *;
