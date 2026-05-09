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

-- name: GetNextLinuxUID :one
SELECT nextval('linux_uid_seq')::INTEGER;

-- name: ListAllNonDeletedUsers :many
SELECT * FROM users_projection
WHERE is_deleted = FALSE
ORDER BY created_at;

-- name: InsertUserProjection :exec
-- UserCreated handler. Mirrors the PL/pgSQL projector's INSERT with
-- has_password derived from password_hash being non-empty. No
-- ON CONFLICT clause: a duplicate UserCreated must surface as an
-- error so the listener log catches the bug (the reconciler does not
-- replay UserCreated against an existing user).
INSERT INTO users_projection (
    id, email, password_hash, role,
    created_at, updated_at, projection_version, session_version, has_password,
    display_name, given_name, family_name, preferred_username, picture, locale,
    linux_username, linux_uid
) VALUES (
    $1, $2, $3, $4,
    $5, $5, $6, 0, $7,
    $8, $9, $10, $11, $12, $13,
    $14, $15
);

-- name: UpdateUserProfileProjection :execrows
-- UserProfileUpdated handler. Each profile field is a plain string —
-- the decoder expanded missing keys to "" already (matches PL/pgSQL
-- COALESCE-to-""). Stale-replay guard via projection_version.
UPDATE users_projection
SET display_name       = $2,
    given_name         = $3,
    family_name        = $4,
    preferred_username = $5,
    picture            = $6,
    locale             = $7,
    updated_at         = $8,
    projection_version = $9
WHERE id = $1
  AND projection_version < $9;

-- name: UpdateUserEmailProjection :execrows
-- UserEmailChanged handler. Stale-replay guard via projection_version.
UPDATE users_projection
SET email              = $2,
    updated_at         = $3,
    projection_version = $4
WHERE id = $1
  AND projection_version < $4;

-- name: UpdateUserPasswordProjection :execrows
-- UserPasswordChanged handler. Bumps session_version monotonically as
-- part of the same guarded UPDATE so a stale replay (whose
-- projection_version fails the guard) cannot reset session_version
-- to a stale value — neither password_hash NOR session_version
-- changes when n == 0.
UPDATE users_projection
SET password_hash      = $2,
    has_password       = TRUE,
    session_version    = session_version + 1,
    updated_at         = $3,
    projection_version = $4
WHERE id = $1
  AND projection_version < $4;

-- name: UpdateUserRoleProjection :execrows
-- UserRoleChanged handler. Stale-replay guard via projection_version.
UPDATE users_projection
SET role               = $2,
    updated_at         = $3,
    projection_version = $4
WHERE id = $1
  AND projection_version < $4;

-- name: InvalidateUserSessionProjection :execrows
-- UserSessionInvalidated handler. Same monotonic-bump rationale as
-- UpdateUserPasswordProjection: the guarded UPDATE rejects a stale
-- replay outright so session_version stays monotonic.
UPDATE users_projection
SET session_version    = session_version + 1,
    updated_at         = $2,
    projection_version = $3
WHERE id = $1
  AND projection_version < $3;

-- name: DisableUserProjection :execrows
-- UserDisabled handler. The session_version + 1 increment is paired
-- with the disabled flag flip inside one guarded UPDATE — a stale
-- Disable replayed after a re-Enable fails the projection_version
-- guard outright (n == 0), so neither disabled NOR session_version
-- regress to the stale value.
UPDATE users_projection
SET disabled           = TRUE,
    session_version    = session_version + 1,
    updated_at         = $2,
    projection_version = $3
WHERE id = $1
  AND projection_version < $3;

-- name: EnableUserProjection :execrows
-- UserEnabled handler. Note: no session_version bump on enable
-- (matches PL/pgSQL — only Disable, PasswordChanged, and
-- SessionInvalidated bump it).
UPDATE users_projection
SET disabled           = FALSE,
    updated_at         = $2,
    projection_version = $3
WHERE id = $1
  AND projection_version < $3;

-- name: UpdateUserLoginProjection :execrows
-- UserLoggedIn handler. PL/pgSQL only stamped last_login_at and
-- projection_version (no updated_at touch). Preserve that exactly.
UPDATE users_projection
SET last_login_at      = $2,
    projection_version = $3
WHERE id = $1
  AND projection_version < $3;

-- name: SoftDeleteUserProjection :execrows
-- UserDeleted handler — first half. Returns rows-affected so the
-- listener can SHORT-CIRCUIT the cascade DELETE on
-- identity_links_projection when the projection_version guard
-- rejects a stale replay. Otherwise an old UserDeleted re-applied by
-- the reconciler would silently nuke a freshly-restored user's
-- identity links (multi-write asymmetric-guard discipline, CR catch
-- on PR #101 pattern).
UPDATE users_projection
SET is_deleted         = TRUE,
    updated_at         = $2,
    projection_version = $3
WHERE id = $1
  AND projection_version < $3;

-- name: DeleteIdentityLinksByUser :exec
-- UserDeleted handler — second half. Cascades the delete to
-- identity_links_projection. Wrapped with SoftDeleteUserProjection
-- in store.WithTx for inter-write atomicity.
DELETE FROM identity_links_projection WHERE user_id = $1;

-- name: AppendUserSshKeyProjection :execrows
-- UserSshKeyAdded handler. Mirrors the PL/pgSQL JSONB array-append
-- exactly: builds a single-element array and concatenates.
-- Stale-replay guard via projection_version.
UPDATE users_projection
SET ssh_public_keys = ssh_public_keys || jsonb_build_array(
        jsonb_build_object(
            'id', @key_id::TEXT,
            'public_key', @public_key::TEXT,
            'comment', @comment::TEXT,
            'added_at', @added_at::TIMESTAMPTZ
        )
    ),
    updated_at         = @added_at::TIMESTAMPTZ,
    projection_version = @projection_version
WHERE id = @id
  AND projection_version < @projection_version;

-- name: RemoveUserSshKeyProjection :execrows
-- UserSshKeyRemoved handler. Mirrors the PL/pgSQL JSONB filter-by-id
-- via subquery exactly — the array filter happens in SQL so we
-- don't read-modify-write the JSONB blob through Go.
-- Stale-replay guard via projection_version.
UPDATE users_projection
SET ssh_public_keys = COALESCE((
        SELECT jsonb_agg(e.value)
        FROM jsonb_array_elements(ssh_public_keys) AS e(value)
        WHERE e.value->>'id' != @key_id::TEXT
    ), '[]'::JSONB),
    updated_at         = $2,
    projection_version = $3
WHERE id = $1
  AND projection_version < $3;

-- name: UpdateUserSshSettingsProjection :execrows
-- UserSshSettingsUpdated handler. Each boolean is COALESCE-preserved
-- via sqlc.narg — nil pointer = SQL NULL = preserve existing column.
-- Stale-replay guard via projection_version.
UPDATE users_projection
SET ssh_access_enabled = COALESCE(sqlc.narg('ssh_access_enabled')::BOOLEAN, ssh_access_enabled),
    ssh_allow_pubkey   = COALESCE(sqlc.narg('ssh_allow_pubkey')::BOOLEAN, ssh_allow_pubkey),
    ssh_allow_password = COALESCE(sqlc.narg('ssh_allow_password')::BOOLEAN, ssh_allow_password),
    updated_at         = sqlc.arg('updated_at'),
    projection_version = sqlc.arg('projection_version')
WHERE id = sqlc.arg('id')
  AND projection_version < sqlc.arg('projection_version');

-- name: UpdateUserLinuxUsernameProjection :execrows
-- UserLinuxUsernameChanged handler. Stale-replay guard via
-- projection_version.
UPDATE users_projection
SET linux_username     = $2,
    updated_at         = $3,
    projection_version = $4
WHERE id = $1
  AND projection_version < $4;

-- name: LinkUserSystemActionProjection :execrows
-- UserSystemActionLinked handler. Mirrors the PL/pgSQL targeted CASE
-- exactly: only the column matching `field` gets the supplied
-- action_id; the other two columns are preserved. The CASE arms are
-- in SQL (not Go) so the column-write decision atomically lines up
-- with the projection_version guard.
-- Stale-replay guard via projection_version.
UPDATE users_projection
SET system_user_action_id = CASE
        WHEN @field::TEXT = 'system_user_action_id' THEN @action_id::TEXT
        ELSE system_user_action_id
    END,
    system_ssh_action_id = CASE
        WHEN @field::TEXT = 'system_ssh_action_id' THEN @action_id::TEXT
        ELSE system_ssh_action_id
    END,
    system_tty_action_id = CASE
        WHEN @field::TEXT = 'system_tty_action_id' THEN @action_id::TEXT
        ELSE system_tty_action_id
    END,
    updated_at         = @updated_at,
    projection_version = @projection_version
WHERE id = @id
  AND projection_version < @projection_version;

-- name: UpdateUserProvisioningSettingsProjection :execrows
-- UserProvisioningSettingsUpdated handler. The single boolean is
-- COALESCE-preserved via sqlc.narg — nil pointer = SQL NULL =
-- preserve existing column. Stale-replay guard via
-- projection_version.
UPDATE users_projection
SET user_provisioning_enabled = COALESCE(sqlc.narg('user_provisioning_enabled')::BOOLEAN, user_provisioning_enabled),
    updated_at                = sqlc.arg('updated_at'),
    projection_version        = sqlc.arg('projection_version')
WHERE id = sqlc.arg('id')
  AND projection_version < sqlc.arg('projection_version');
