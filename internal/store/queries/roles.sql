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
