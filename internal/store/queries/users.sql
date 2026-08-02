-- name: InsertUser :one
-- A user carries no authorization of its own: what the subject may do
-- comes from user_roles and user_group_roles.
INSERT INTO users (
    id, email, display_name, given_name, family_name, preferred_username,
    linux_username, linux_uid, provisioning_source, created_at, updated_at
)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
RETURNING *;

-- name: GetUser :one
SELECT * FROM users WHERE id = ? AND is_deleted = FALSE;

-- name: GetUserByEmail :one
SELECT * FROM users WHERE email = ? AND is_deleted = FALSE;

-- name: GetUserSessionState :one
-- Deliberately unfiltered by is_deleted: the refresh path must be able
-- to tell a retired subject from an unknown one and refuse both.
SELECT id, disabled, is_deleted, session_version FROM users WHERE id = ?;

-- name: ListUsers :many
-- Keyset pagination on the ULID primary key: ULIDs sort by mint time,
-- so ordering by id is a stable cursor a concurrent insert cannot
-- shift rows across.
SELECT * FROM users
WHERE is_deleted = FALSE AND id > ?
ORDER BY id
LIMIT ?;

-- name: UpdateUserEmail :execrows
UPDATE users SET email = ?, updated_at = ? WHERE id = ? AND is_deleted = FALSE;

-- name: UpdateUserProfile :one
UPDATE users
SET display_name = ?,
    given_name = ?,
    family_name = ?,
    preferred_username = ?,
    picture = ?,
    locale = ?,
    updated_at = ?
WHERE id = ? AND is_deleted = FALSE
RETURNING *;

-- name: UpdateUserSshSettings :one
UPDATE users
SET ssh_access_enabled = ?, ssh_allow_pubkey = ?, ssh_allow_password = ?, updated_at = ?
WHERE id = ? AND is_deleted = FALSE
RETURNING *;

-- name: UpdateUserLinuxUsername :one
UPDATE users SET linux_username = ?, updated_at = ?
WHERE id = ? AND is_deleted = FALSE
RETURNING *;

-- name: SetUserProvisioningEnabled :one
UPDATE users SET user_provisioning_enabled = ?, updated_at = ?
WHERE id = ? AND is_deleted = FALSE
RETURNING *;

-- name: SetUserDisabled :execrows
-- Disabling bumps session_version in the same statement, so every
-- session already issued to the subject stops validating at once.
UPDATE users
SET disabled = sqlc.arg(disabled), session_version = session_version + 1, updated_at = sqlc.arg(updated_at)
WHERE id = sqlc.arg(id) AND is_deleted = FALSE AND disabled <> sqlc.arg(disabled);

-- name: BumpUserSessionVersion :one
-- Any change to what a subject may do invalidates the sessions minted
-- under the old authority. The new value is returned so the caller can
-- record the transition as audit evidence.
UPDATE users SET session_version = session_version + 1, updated_at = ?
WHERE id = ? AND is_deleted = FALSE
RETURNING session_version;

-- name: TouchUserLastLogin :execrows
UPDATE users SET last_login_at = ?, updated_at = ? WHERE id = ? AND is_deleted = FALSE;

-- name: DeleteUser :execrows
-- Erasure of ordinary personal state. The subject's DEK is destroyed
-- separately, which is what makes the sealed audit detail unreadable.
DELETE FROM users WHERE id = ?;

-- name: CountUsers :one
SELECT COUNT(*) FROM users WHERE is_deleted = FALSE;

-- name: GetNextLinuxUID :one
UPDATE linux_uid_sequence
SET next_value = next_value + 1
WHERE id = 1
RETURNING next_value - 1;

-- name: GetServerSettings :one
SELECT * FROM server_settings WHERE id = '00000000000000000000000003';

-- name: UpdateServerSettings :one
UPDATE server_settings
SET user_provisioning_enabled = sqlc.arg(user_provisioning_enabled),
    ssh_access_for_all = sqlc.arg(ssh_access_for_all),
    updated_at = sqlc.arg(updated_at)
WHERE id = '00000000000000000000000003'
RETURNING *;
