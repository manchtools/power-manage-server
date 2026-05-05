-- name: GetRoleByID :one
SELECT * FROM roles_projection WHERE id = $1 AND is_deleted = FALSE;

-- name: GetRoleByName :one
SELECT * FROM roles_projection WHERE name = $1 AND is_deleted = FALSE;

-- name: ListRoles :many
SELECT * FROM roles_projection WHERE is_deleted = FALSE ORDER BY name LIMIT $1 OFFSET $2;

-- name: CountRoles :one
SELECT count(*) FROM roles_projection WHERE is_deleted = FALSE;

-- name: GetUserRoles :many
SELECT r.* FROM roles_projection r
JOIN user_roles_projection ur ON ur.role_id = r.id
WHERE ur.user_id = $1 AND r.is_deleted = FALSE
ORDER BY r.name;

-- name: GetUserPermissions :many
SELECT DISTINCT unnest(r.permissions)::TEXT AS permission FROM roles_projection r
JOIN user_roles_projection ur ON ur.role_id = r.id
WHERE ur.user_id = $1 AND r.is_deleted = FALSE;

-- name: CountUsersWithRole :one
SELECT count(*) FROM user_roles_projection WHERE role_id = $1;

-- name: ListUserIDsWithRole :many
SELECT user_id FROM user_roles_projection WHERE role_id = $1;

-- name: UserHasRole :one
SELECT EXISTS(SELECT 1 FROM user_roles_projection WHERE user_id = $1 AND role_id = $2) AS has_role;

-- name: UpdateSystemRolePermissions :execrows
UPDATE roles_projection SET permissions = $1, updated_at = NOW() WHERE id = $2 AND is_system = TRUE;

-- name: InsertRoleProjection :exec
-- RoleCreated handler. ON CONFLICT DO NOTHING for replay safety —
-- the reconciler may re-deliver the event; if a row already exists
-- under the same id, leave it alone (RoleUpdated owns mutations).
INSERT INTO roles_projection (
    id, name, description, permissions, is_system,
    created_at, created_by, projection_version
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (id) DO NOTHING;

-- name: UpdateRoleProjection :exec
-- RoleUpdated handler. nil pointers from the listener collapse to
-- SQL NULL, which COALESCE preserves the existing column. Empty-
-- string Name is converted to nil at the listener layer (NULLIF
-- equivalent), so this query treats both omitted and empty Name
-- identically. The `projection_version` guard rejects stale
-- reconciler replays.
UPDATE roles_projection
SET name              = COALESCE(sqlc.narg('name')::TEXT, name),
    description       = COALESCE(sqlc.narg('description')::TEXT, description),
    permissions       = COALESCE(sqlc.narg('permissions')::TEXT[], permissions),
    updated_at        = sqlc.arg('updated_at'),
    projection_version = sqlc.arg('projection_version')
WHERE id = sqlc.arg('id')
  AND projection_version < sqlc.arg('projection_version');

-- name: SoftDeleteRoleProjection :execrows
-- RoleDeleted handler — first half. Marks the role as deleted but
-- leaves the row so the audit log resolves role names. Listener
-- pairs this with DeleteUserRolesByRole inside store.WithTx so the
-- projection never observes "role deleted but memberships remain".
-- Returns rows-affected so the listener can SKIP the cascade
-- DeleteUserRolesByRole when the projection_version guard rejects
-- a stale replay; otherwise an old RoleDeleted re-applied by the
-- reconciler would silently nuke a freshly-restored role's
-- memberships.
UPDATE roles_projection
SET is_deleted        = TRUE,
    updated_at        = $2,
    projection_version = $3
WHERE id = $1
  AND projection_version < $3;

-- name: DeleteUserRolesByRole :exec
-- RoleDeleted handler — second half. Cascades the delete to
-- user_roles_projection so user-permission queries no longer surface
-- this role's permissions. Wrapped with SoftDeleteRoleProjection in
-- store.WithTx for inter-write atomicity.
DELETE FROM user_roles_projection WHERE role_id = $1;

-- name: InsertUserRoleProjection :exec
-- UserRoleAssigned handler. ON CONFLICT (user_id, role_id) DO NOTHING
-- preserves the PL/pgSQL projector's idempotency under reconciler
-- replays.
INSERT INTO user_roles_projection (
    user_id, role_id, assigned_at, assigned_by, projection_version
) VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (user_id, role_id) DO NOTHING;

-- name: DeleteUserRoleProjection :exec
-- UserRoleRevoked handler. Plain DELETE — silently no-op on a miss
-- matches the PL/pgSQL projector's behaviour under repeated revoke
-- events.
DELETE FROM user_roles_projection
WHERE user_id = $1
  AND role_id = $2;
