-- Roles are the authorization catalogue: a named, ordered set of
-- permission keys. What a subject may do is the union of the roles
-- granted to them directly and through their groups; the role row
-- itself names nobody.

-- name: InsertRole :one
INSERT INTO roles (id, name, description, permissions, is_system, created_at, created_by, updated_at)
VALUES (?, ?, ?, ?, FALSE, ?, ?, ?)
RETURNING *;

-- name: GetRole :one
SELECT * FROM roles WHERE id = ? AND is_deleted = FALSE;

-- name: GetRoleByName :one
SELECT * FROM roles WHERE name = ? AND is_deleted = FALSE;

-- name: ListRoles :many
-- Keyset pagination on the ULID primary key: ULIDs sort by mint time,
-- so ordering by id is a stable, gap-free cursor that a concurrent
-- insert cannot shift rows across.
SELECT * FROM roles
WHERE is_deleted = FALSE AND id > ?
ORDER BY id
LIMIT ?;

-- name: CountRoles :one
SELECT COUNT(*) FROM roles WHERE is_deleted = FALSE;

-- name: UpdateRole :one
-- System roles are reconciled from the code registry on boot; letting a
-- handler rewrite one would be silently undone at the next start, so the
-- statement refuses them outright.
UPDATE roles
SET name = ?, description = ?, permissions = ?, updated_at = ?
WHERE id = ? AND is_deleted = FALSE AND is_system = FALSE
RETURNING *;

-- name: SoftDeleteRole :execrows
UPDATE roles SET is_deleted = TRUE, updated_at = ?
WHERE id = ? AND is_deleted = FALSE AND is_system = FALSE;

-- name: UpdateSystemRolePermissions :execrows
-- The boot-time reconciler's only write: it refreshes a system role's
-- permission array from the code registry.
UPDATE roles SET permissions = ?, updated_at = ?
WHERE id = ? AND is_system = TRUE AND is_deleted = FALSE;

-- name: CountRoleHolders :one
-- How many distinct subjects hold the role, directly or through a group.
SELECT COUNT(*) FROM (
    SELECT ur.user_id FROM user_roles ur WHERE ur.role_id = sqlc.arg(role_id)
    UNION
    SELECT m.user_id
      FROM user_group_roles gr
      JOIN user_group_members m ON m.group_id = gr.group_id
     WHERE gr.role_id = sqlc.arg(role_id)
) holders;

-- name: BumpSessionVersionForRoleHolders :execrows
-- Changing what a role may do changes what everyone holding it may do,
-- so every session minted under the previous permission set is
-- invalidated in the same statement: directly-granted holders and
-- group-inherited holders alike.
UPDATE users SET session_version = session_version + 1, updated_at = ?
WHERE is_deleted = FALSE AND id IN (
    SELECT ur.user_id FROM user_roles ur WHERE ur.role_id = sqlc.arg(role_id)
    UNION
    SELECT m.user_id
      FROM user_group_roles gr
      JOIN user_group_members m ON m.group_id = gr.group_id
     WHERE gr.role_id = sqlc.arg(role_id)
);
