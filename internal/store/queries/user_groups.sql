-- name: GetUserGroupByID :one
SELECT * FROM user_groups_projection WHERE id = $1 AND is_deleted = FALSE;

-- name: GetUserGroupByName :one
SELECT * FROM user_groups_projection WHERE name = $1 AND is_deleted = FALSE;

-- name: ListUserGroups :many
SELECT * FROM user_groups_projection WHERE is_deleted = FALSE ORDER BY name LIMIT $1 OFFSET $2;

-- name: CountUserGroups :one
SELECT count(*) FROM user_groups_projection WHERE is_deleted = FALSE;

-- name: ListUserGroupMembers :many
SELECT ugm.user_id, u.email, ugm.added_at
FROM user_group_members_projection ugm
JOIN users_projection u ON u.id = ugm.user_id AND u.is_deleted = FALSE
WHERE ugm.group_id = $1
ORDER BY ugm.added_at;

-- name: IsUserInGroup :one
SELECT EXISTS(
    SELECT 1 FROM user_group_members_projection
    WHERE group_id = $1 AND user_id = $2
) AS is_member;

-- name: GetUserGroupRoles :many
SELECT r.* FROM roles_projection r
JOIN user_group_roles_projection ugr ON ugr.role_id = r.id
WHERE ugr.group_id = $1 AND r.is_deleted = FALSE
ORDER BY r.name;

-- name: UserGroupHasRole :one
SELECT EXISTS(
    SELECT 1 FROM user_group_roles_projection
    WHERE group_id = $1 AND role_id = $2
) AS has_role;

-- name: ListUserGroupsForUser :many
SELECT ug.* FROM user_groups_projection ug
JOIN user_group_members_projection ugm ON ugm.group_id = ug.id
WHERE ugm.user_id = $1 AND ug.is_deleted = FALSE
ORDER BY ug.name;

-- name: ListUserGroupMemberIDs :many
SELECT user_id FROM user_group_members_projection WHERE group_id = $1;

-- name: CountGroupsWithRole :one
SELECT count(*) FROM user_group_roles_projection WHERE role_id = $1;

-- name: ListUserIDsWithGroupRole :many
SELECT DISTINCT ugm.user_id
FROM user_group_members_projection ugm
JOIN user_group_roles_projection ugr ON ugr.group_id = ugm.group_id
WHERE ugr.role_id = $1;

-- name: GetUserPermissionsWithGroups :many
SELECT DISTINCT unnest(r.permissions)::TEXT AS permission
FROM roles_projection r
WHERE r.is_deleted = FALSE AND (
    r.id IN (SELECT ur.role_id FROM user_roles_projection ur WHERE ur.user_id = $1)
    OR
    r.id IN (
        SELECT ugr.role_id FROM user_group_roles_projection ugr
        JOIN user_group_members_projection ugm ON ugm.group_id = ugr.group_id
        WHERE ugm.user_id = $1
    )
);
