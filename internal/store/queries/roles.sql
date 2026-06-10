-- name: GetRoleByID :one
SELECT * FROM roles_projection WHERE id = $1 AND is_deleted = FALSE;

-- name: GetRoleByName :one
SELECT * FROM roles_projection WHERE name = $1 AND is_deleted = FALSE;

-- name: ListRoles :many
SELECT * FROM roles_projection WHERE is_deleted = FALSE ORDER BY name LIMIT $1 OFFSET $2;

-- name: CountRoles :one
SELECT count(*) FROM roles_projection WHERE is_deleted = FALSE;

-- name: GetUserRoles :many
-- DISTINCT because a role can now be granted to a user multiple times at
-- different scopes (#7); this de-duplicated, scope-blind set backs the
-- legacy User.roles field. The per-grant view is GetUserRoleGrants.
SELECT DISTINCT r.* FROM roles_projection r
JOIN user_roles_projection ur ON ur.role_id = r.id
WHERE ur.user_id = $1 AND r.is_deleted = FALSE
ORDER BY r.name;

-- name: GetUserPermissions :many
SELECT DISTINCT unnest(r.permissions)::TEXT AS permission FROM roles_projection r
JOIN user_roles_projection ur ON ur.role_id = r.id
WHERE ur.user_id = $1 AND r.is_deleted = FALSE;

-- name: GetUserScopedGrants :many
-- Returns every (permission, scope) tuple the user holds — from direct
-- role grants AND grants inherited via user-group membership — carrying
-- the grant's (scope_kind, scope_id). Both are NULL for an unscoped
-- (global) grant. DISTINCT collapses the same permission held at the
-- same scope via multiple roles. Drives the JWT `sgrants` claim and the
-- scope-enforcement primitives (#7 S2b). The cascade is a property of
-- the GRANT: every permission a grant materializes inherits the grant's
-- scope.
SELECT grants.permission, grants.scope_kind, grants.scope_id FROM (
    SELECT perm.permission::TEXT AS permission, ur.scope_kind, ur.scope_id
    FROM roles_projection r
    JOIN user_roles_projection ur ON ur.role_id = r.id
    CROSS JOIN LATERAL unnest(r.permissions) AS perm(permission)
    WHERE ur.user_id = $1 AND r.is_deleted = FALSE
    UNION
    SELECT perm.permission::TEXT AS permission, ugr.scope_kind, ugr.scope_id
    FROM roles_projection r
    JOIN user_group_roles_projection ugr ON ugr.role_id = r.id
    JOIN user_group_members_projection ugm ON ugm.group_id = ugr.group_id
    CROSS JOIN LATERAL unnest(r.permissions) AS perm(permission)
    WHERE ugm.user_id = $1 AND r.is_deleted = FALSE
) grants;

-- name: GetUserRoleGrants :many
-- #7 scoped-grant round-trip. Returns the user's DIRECTLY-assigned role
-- grants WITH each grant's scope (NOT de-duplicated — the same role
-- granted globally and scoped to a device group yields two rows), and
-- resolves scope_name from the device-/user-group projection (COALESCE to
-- '' when unscoped or the group was deleted). Drives User.role_grants for
-- scoped-grant display + revocation. Hand-maintained: scope_kind/scope_id
-- live in migration 010's DO-block, which sqlc cannot resolve (#336).
SELECT r.id, r.name, r.description, r.permissions, r.is_system,
       r.created_at, r.created_by, r.updated_at,
       ur.scope_kind, ur.scope_id,
       COALESCE(dg.name, ug.name, '')::TEXT AS scope_name
FROM roles_projection r
JOIN user_roles_projection ur ON ur.role_id = r.id
LEFT JOIN device_groups_projection dg
       ON ur.scope_kind = 'device_group' AND dg.id = ur.scope_id AND dg.is_deleted = FALSE
LEFT JOIN user_groups_projection ug
       ON ur.scope_kind = 'user_group' AND ug.id = ur.scope_id AND ug.is_deleted = FALSE
WHERE ur.user_id = $1 AND r.is_deleted = FALSE
ORDER BY r.name, ur.scope_id NULLS FIRST;

-- name: GetUserGroupRoleGrants :many
-- #7 scoped-grant round-trip for a user group's own role grants. Same
-- shape + scope_name resolution as GetUserRoleGrants; drives
-- UserGroup.role_grants. Hand-maintained (DO-block scope columns).
SELECT r.id, r.name, r.description, r.permissions, r.is_system,
       r.created_at, r.created_by, r.updated_at,
       ugr.scope_kind, ugr.scope_id,
       COALESCE(dg.name, ug.name, '')::TEXT AS scope_name
FROM roles_projection r
JOIN user_group_roles_projection ugr ON ugr.role_id = r.id
LEFT JOIN device_groups_projection dg
       ON ugr.scope_kind = 'device_group' AND dg.id = ugr.scope_id AND dg.is_deleted = FALSE
LEFT JOIN user_groups_projection ug
       ON ugr.scope_kind = 'user_group' AND ug.id = ugr.scope_id AND ug.is_deleted = FALSE
WHERE ugr.group_id = $1 AND r.is_deleted = FALSE
ORDER BY r.name, ugr.scope_id NULLS FIRST;

-- name: CountUsersWithRole :one
SELECT count(*) FROM user_roles_projection WHERE role_id = $1;

-- name: ListUserIDsWithRole :many
SELECT user_id FROM user_roles_projection WHERE role_id = $1;

-- name: UserHasRole :one
SELECT EXISTS(SELECT 1 FROM user_roles_projection WHERE user_id = $1 AND role_id = $2) AS has_role;

-- name: UserHasUnscopedRole :one
-- Scope-aware variant: does the user hold this role as an UNSCOPED
-- (global) grant specifically? The assign-role redundancy pre-check uses
-- this so an unscoped assign isn't dropped when only a SCOPED grant of the
-- same role exists (#7 grant independence). Hand-maintained: scope_id is a
-- migration-010 DO-block column sqlc cannot resolve (#336).
SELECT EXISTS(SELECT 1 FROM user_roles_projection
              WHERE user_id = $1 AND role_id = $2 AND scope_id IS NULL) AS has_role;

-- name: UserHasScopedRole :one
-- Existence of a SPECIFIC (user, role, scope) grant. IS NOT DISTINCT
-- FROM is NULL-aware: NULL scope params match the unscoped grant; set
-- params match that exact scoped grant. Used by RevokeRoleFromUser to
-- reject "revoke a grant that doesn't exist" rather than silently
-- no-op (server #7 S5).
SELECT EXISTS(
    SELECT 1 FROM user_roles_projection
    WHERE user_id = $1 AND role_id = $2
      AND scope_kind IS NOT DISTINCT FROM sqlc.narg('scope_kind')::TEXT
      AND scope_id   IS NOT DISTINCT FROM sqlc.narg('scope_id')::TEXT
) AS has_role;

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
-- UserRoleAssigned handler. Scope columns (scope_kind, scope_id)
-- are NULL together for unscoped grants and both set for scoped
-- grants (paired-or-neither, enforced by the DB CHECK as well as
-- the projector). ON CONFLICT DO NOTHING (no target) catches both
-- partial unique indexes — unscoped_unique and scoped_unique — so
-- a reconciler replay of either shape no-ops cleanly. server #7 S2.
INSERT INTO user_roles_projection (
    user_id, role_id, scope_kind, scope_id,
    assigned_at, assigned_by, projection_version
) VALUES (
    $1, $2,
    sqlc.narg('scope_kind')::TEXT,
    sqlc.narg('scope_id')::TEXT,
    $3, $4, $5
)
ON CONFLICT DO NOTHING;

-- name: DeleteUserRoleProjection :exec
-- UserRoleRevoked handler — 4-tuple revoke grammar (server #7 S5).
-- IS NOT DISTINCT FROM gives NULL-aware equality: when the caller
-- passes NULL for both scope_kind and scope_id the WHERE matches
-- the row whose scope columns are also both NULL (the unscoped
-- grant); when the caller passes concrete values it targets the
-- specific scoped row. A miss is a silent no-op, matching the
-- prior projector behaviour.
DELETE FROM user_roles_projection
WHERE user_id = $1
  AND role_id = $2
  AND scope_kind IS NOT DISTINCT FROM sqlc.narg('scope_kind')::TEXT
  AND scope_id   IS NOT DISTINCT FROM sqlc.narg('scope_id')::TEXT;
