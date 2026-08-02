-- Role grants: which subject holds which role, and at which scope.
--
-- A grant is identified by its own ULID because one subject may hold
-- the same role globally AND at several distinct scopes at once.
-- scope_kind/scope_id are paired-or-neither; both NULL is a global
-- grant. Revocation names one grant, never "the role".

-- name: InsertUserRoleGrant :one
INSERT INTO user_roles (grant_id, user_id, role_id, assigned_at, assigned_by, scope_kind, scope_id)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING *;

-- name: DeleteUnscopedUserRoleGrant :one
-- Conditional on the grant being the UNSCOPED one: a caller asking to
-- revoke the global grant must not silently take a scoped grant
-- instead. No row means the caller's description did not match.
DELETE FROM user_roles
WHERE user_id = $1 AND role_id = $2 AND scope_id IS NULL
RETURNING *;

-- name: DeleteScopedUserRoleGrant :one
DELETE FROM user_roles
WHERE user_id = $1 AND role_id = $2 AND scope_kind = $3 AND scope_id = $4
RETURNING *;

-- name: DeleteUserRoleGrantsForUser :execrows
DELETE FROM user_roles WHERE user_id = $1;

-- name: ListUserRoleGrants :many
SELECT
    ur.grant_id,
    ur.scope_kind,
    ur.scope_id,
    sqlc.embed(r)
FROM user_roles ur
JOIN roles r ON r.id = ur.role_id
WHERE ur.user_id = $1 AND r.is_deleted = FALSE
ORDER BY ur.grant_id;

-- name: InsertUserGroupRoleGrant :one
INSERT INTO user_group_roles (grant_id, group_id, role_id, assigned_at, assigned_by, scope_kind, scope_id)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING *;

-- name: DeleteUnscopedUserGroupRoleGrant :one
DELETE FROM user_group_roles
WHERE group_id = $1 AND role_id = $2 AND scope_id IS NULL
RETURNING *;

-- name: DeleteScopedUserGroupRoleGrant :one
DELETE FROM user_group_roles
WHERE group_id = $1 AND role_id = $2 AND scope_kind = $3 AND scope_id = $4
RETURNING *;

-- name: ListUserGroupRoleGrants :many
SELECT
    gr.grant_id,
    gr.scope_kind,
    gr.scope_id,
    sqlc.embed(r)
FROM user_group_roles gr
JOIN roles r ON r.id = gr.role_id
WHERE gr.group_id = $1 AND r.is_deleted = FALSE
ORDER BY gr.grant_id;

-- name: ListInheritedRolesForUser :many
-- Roles the subject holds because of a group they belong to. Reported
-- separately from direct grants so a UI can show where authority came
-- from without inventing a second grant surface.
SELECT
    r.id   AS role_id,
    r.name AS role_name,
    g.id   AS group_id,
    g.name AS group_name
FROM user_group_members m
JOIN user_groups g ON g.id = m.group_id AND g.is_deleted = FALSE
JOIN user_group_roles gr ON gr.group_id = m.group_id
JOIN roles r ON r.id = gr.role_id AND r.is_deleted = FALSE
WHERE m.user_id = $1
ORDER BY r.id, g.id;

-- name: ListUserPermissions :many
-- The flat permission set the session token carries: the union of every
-- permission in every role the subject holds, directly or by group.
SELECT DISTINCT s.permission::text AS permission
FROM (
    SELECT unnest(r.permissions) AS permission
      FROM user_roles ur
      JOIN roles r ON r.id = ur.role_id AND r.is_deleted = FALSE
     WHERE ur.user_id = $1
    UNION ALL
    SELECT unnest(r.permissions) AS permission
      FROM user_group_members m
      JOIN user_group_roles gr ON gr.group_id = m.group_id
      JOIN roles r ON r.id = gr.role_id AND r.is_deleted = FALSE
     WHERE m.user_id = $1
) s
ORDER BY permission;

-- name: ListUserScopedGrants :many
-- The same permissions, one row per (permission, scope) tuple. A NULL
-- scope is the global grant of that permission; the evaluator treats
-- it as fleet-wide and a group scope as confinement.
SELECT DISTINCT s.permission::text AS permission, s.scope_kind, s.scope_id
FROM (
    SELECT unnest(r.permissions) AS permission, ur.scope_kind, ur.scope_id
      FROM user_roles ur
      JOIN roles r ON r.id = ur.role_id AND r.is_deleted = FALSE
     WHERE ur.user_id = $1
    UNION ALL
    SELECT unnest(r.permissions) AS permission, gr.scope_kind, gr.scope_id
      FROM user_group_members m
      JOIN user_group_roles gr ON gr.group_id = m.group_id
      JOIN roles r ON r.id = gr.role_id AND r.is_deleted = FALSE
     WHERE m.user_id = $1
) s
ORDER BY permission, s.scope_kind NULLS FIRST, s.scope_id;

-- name: ListUserGroupIDsForUser :many
SELECT m.group_id
FROM user_group_members m
JOIN user_groups g ON g.id = m.group_id AND g.is_deleted = FALSE
WHERE m.user_id = $1
ORDER BY m.group_id;

-- name: DeleteUserGroupMembershipsForUser :execrows
DELETE FROM user_group_members WHERE user_id = $1;

-- name: BumpSessionVersionForUserGroupMembers :execrows
UPDATE users
SET session_version = session_version + 1, updated_at = sqlc.arg(updated_at)
WHERE is_deleted = FALSE
  AND id IN (SELECT user_id FROM user_group_members WHERE group_id = sqlc.arg(group_id));
