-- User groups. A group is a container for subjects; the authority it
-- confers lives in user_group_roles, so a membership write is an
-- authorization change and every one of them is audited.

-- name: InsertUserGroup :one
INSERT INTO user_groups (id, name, description, created_at, created_by, updated_at, is_dynamic, dynamic_query)
VALUES (?, ?, ?, ?, ?, ?, sqlc.arg(is_dynamic), sqlc.narg(dynamic_query))
RETURNING *;

-- name: GetUserGroup :one
SELECT * FROM user_groups WHERE id = ? AND is_deleted = FALSE;

-- name: GetUserGroupView :one
SELECT g.id, g.name, g.description, g.created_at, g.created_by,
       g.is_dynamic, g.dynamic_query, g.maintenance_window,
       COUNT(u.id) AS live_member_count,
       EXISTS (SELECT 1 FROM scim_group_mapping sgm WHERE sgm.user_group_id = g.id) AS is_scim_managed
FROM user_groups g
LEFT JOIN user_group_members m ON m.group_id = g.id
LEFT JOIN users u ON u.id = m.user_id AND u.is_deleted = FALSE
WHERE g.id = ? AND g.is_deleted = FALSE
GROUP BY g.id;

-- name: ListUserGroups :many
SELECT g.id, g.name, g.description, g.created_at, g.created_by,
       g.is_dynamic, g.dynamic_query, g.maintenance_window,
       COUNT(u.id) AS live_member_count,
       EXISTS (SELECT 1 FROM scim_group_mapping sgm WHERE sgm.user_group_id = g.id) AS is_scim_managed
FROM user_groups g
LEFT JOIN user_group_members m ON m.group_id = g.id
LEFT JOIN users u ON u.id = m.user_id AND u.is_deleted = FALSE
WHERE g.is_deleted = FALSE
  AND g.id > sqlc.arg(after_id)
  AND (
      NOT sqlc.arg(scope_restricted)
      OR g.id IN (SELECT CAST(value AS TEXT) FROM json_each(sqlc.arg(scope_group_ids_json)))
  )
GROUP BY g.id
ORDER BY g.id
LIMIT sqlc.arg(row_limit);

-- name: CountUserGroups :one
SELECT COUNT(*) FROM user_groups g
WHERE g.is_deleted = FALSE
  AND (
      NOT sqlc.arg(scope_restricted)
      OR g.id IN (SELECT CAST(value AS TEXT) FROM json_each(sqlc.arg(scope_group_ids_json)))
  );

-- name: ListUserGroupsForUser :many
SELECT g.id, g.name, g.description, g.created_at, g.created_by,
       g.is_dynamic, g.dynamic_query, g.maintenance_window,
       COUNT(live.id) AS live_member_count,
       EXISTS (SELECT 1 FROM scim_group_mapping sgm WHERE sgm.user_group_id = g.id) AS is_scim_managed
FROM user_group_members requested
JOIN user_groups g ON g.id = requested.group_id AND g.is_deleted = FALSE
LEFT JOIN user_group_members members ON members.group_id = g.id
LEFT JOIN users live ON live.id = members.user_id AND live.is_deleted = FALSE
WHERE requested.user_id = sqlc.arg(user_id)
  AND (
      NOT sqlc.arg(scope_restricted)
      OR g.id IN (SELECT CAST(value AS TEXT) FROM json_each(sqlc.arg(scope_group_ids_json)))
  )
GROUP BY g.id
ORDER BY g.id;

-- name: IsUserGroupSCIMManaged :one
SELECT EXISTS (SELECT 1 FROM scim_group_mapping WHERE user_group_id = ?);

-- name: UpdateUserGroup :one
UPDATE user_groups
SET name = sqlc.arg(name), description = sqlc.arg(description), updated_at = sqlc.arg(updated_at)
WHERE id = sqlc.arg(id) AND is_deleted = FALSE
RETURNING *;

-- name: GetDynamicUserGroupQueryForUpdate :one
SELECT is_dynamic, dynamic_query
FROM user_groups
WHERE id = ? AND is_deleted = FALSE;

-- name: ListUsersForDynamicUserGroupEvaluation :many
SELECT id, email, disabled, display_name, preferred_username, locale
FROM users
WHERE is_deleted = FALSE
ORDER BY id;

-- name: UpdateUserGroupQuery :one
UPDATE user_groups
SET is_dynamic = sqlc.arg(is_dynamic), dynamic_query = sqlc.narg(dynamic_query), updated_at = sqlc.arg(updated_at)
WHERE id = sqlc.arg(id) AND is_deleted = FALSE
RETURNING *;

-- name: BumpUserSessionsByIDs :execrows
UPDATE users
SET session_version = session_version + 1, updated_at = sqlc.arg(updated_at)
WHERE id IN (sqlc.slice(user_ids)) AND is_deleted = FALSE;

-- name: SetUserGroupMaintenanceWindow :one
UPDATE user_groups SET maintenance_window = sqlc.arg(maintenance_window), updated_at = sqlc.arg(updated_at)
WHERE id = sqlc.arg(id) AND is_deleted = FALSE
RETURNING *;

-- name: DeleteUserGroupMembers :execrows
DELETE FROM user_group_members WHERE group_id = ?;

-- name: DeleteUserGroupRoleGrants :execrows
DELETE FROM user_group_roles WHERE group_id = ?;

-- name: DeleteUserGroupAssignments :execrows
UPDATE assignments SET is_deleted = TRUE
WHERE target_type = 'user_group' AND target_id = ? AND is_deleted = FALSE;

-- name: DeleteUserGroupUserRoleScopes :execrows
DELETE FROM user_roles WHERE scope_kind = 'user_group' AND scope_id = ?;

-- name: DeleteUserGroupUserGroupRoleScopes :execrows
DELETE FROM user_group_roles WHERE scope_kind = 'user_group' AND scope_id = ?;

-- name: BumpSessionsAffectedByUserGroupDelete :execrows
UPDATE users SET session_version = session_version + 1, updated_at = sqlc.arg(updated_at)
WHERE is_deleted = FALSE AND id IN (
    SELECT m.user_id FROM user_group_members m WHERE m.group_id = sqlc.arg(group_id)
    UNION
    SELECT ur.user_id FROM user_roles ur
    WHERE ur.scope_kind = 'user_group' AND ur.scope_id = sqlc.arg(group_id)
    UNION
    SELECT m.user_id
    FROM user_group_roles gr
    JOIN user_group_members m ON m.group_id = gr.group_id
    WHERE gr.scope_kind = 'user_group' AND gr.scope_id = sqlc.arg(group_id)
);

-- name: SoftDeleteUserGroup :one
UPDATE user_groups SET is_deleted = TRUE, updated_at = sqlc.arg(updated_at)
WHERE id = sqlc.arg(id) AND is_deleted = FALSE
RETURNING *;

-- name: UpdateUserGroupName :one
UPDATE user_groups SET name = ?, updated_at = ?
WHERE id = ? AND is_deleted = FALSE
RETURNING *;
