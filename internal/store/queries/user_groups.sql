-- User groups. A group is a container for subjects; the authority it
-- confers lives in user_group_roles, so a membership write is an
-- authorization change and every one of them is audited.

-- name: InsertUserGroup :one
INSERT INTO user_groups (id, name, description, created_at, created_by, updated_at)
VALUES ($1, $2, $3, $4, $5, $4)
RETURNING *;

-- name: GetUserGroup :one
SELECT * FROM user_groups WHERE id = $1 AND is_deleted = FALSE;

-- name: UpdateUserGroupName :one
UPDATE user_groups SET name = $2, updated_at = $3
WHERE id = $1 AND is_deleted = FALSE
RETURNING *;
