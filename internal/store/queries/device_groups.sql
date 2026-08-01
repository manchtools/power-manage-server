-- name: GetDeviceGroup :one
SELECT g.id, g.name, g.description, g.created_at, g.created_by,
       g.is_dynamic, g.dynamic_query, g.sync_interval_minutes,
       g.inventory_interval_minutes, g.maintenance_window,
       COUNT(d.id)::bigint AS live_member_count
FROM device_groups g
LEFT JOIN device_group_members m ON m.group_id = g.id
LEFT JOIN devices d ON d.id = m.device_id AND d.is_deleted = FALSE
WHERE g.id = $1 AND g.is_deleted = FALSE
GROUP BY g.id;

-- name: ListDeviceGroups :many
SELECT g.id, g.name, g.description, g.created_at, g.created_by,
       g.is_dynamic, g.dynamic_query, g.sync_interval_minutes,
       g.inventory_interval_minutes, g.maintenance_window,
       COUNT(d.id)::bigint AS live_member_count
FROM device_groups g
LEFT JOIN device_group_members m ON m.group_id = g.id
LEFT JOIN devices d ON d.id = m.device_id AND d.is_deleted = FALSE
WHERE g.is_deleted = FALSE
  AND g.id > sqlc.arg(after_id)
  AND (
      NOT sqlc.arg(scope_restricted)::boolean
      OR g.id = ANY(sqlc.arg(scope_group_ids)::text[])
  )
GROUP BY g.id
ORDER BY g.id
LIMIT sqlc.arg(row_limit);

-- name: CountDeviceGroups :one
SELECT COUNT(*) FROM device_groups g
WHERE g.is_deleted = FALSE
  AND (
      NOT sqlc.arg(scope_restricted)::boolean
      OR g.id = ANY(sqlc.arg(scope_group_ids)::text[])
  );

-- name: ListDeviceGroupsForDevice :many
SELECT g.id, g.name, g.description, g.created_at, g.created_by,
       g.is_dynamic, g.dynamic_query, g.sync_interval_minutes,
       g.inventory_interval_minutes, g.maintenance_window,
       COUNT(live.id)::bigint AS live_member_count
FROM device_group_members requested
JOIN device_groups g ON g.id = requested.group_id AND g.is_deleted = FALSE
LEFT JOIN device_group_members members ON members.group_id = g.id
LEFT JOIN devices live ON live.id = members.device_id AND live.is_deleted = FALSE
WHERE requested.device_id = sqlc.arg(device_id)
  AND (
      NOT sqlc.arg(scope_restricted)::boolean
      OR g.id = ANY(sqlc.arg(scope_group_ids)::text[])
  )
GROUP BY g.id
ORDER BY g.id;

-- name: ListDeviceGroupMembers :many
SELECT d.id AS device_id, d.hostname, d.agent_version, d.last_seen_at
FROM device_group_members m
JOIN devices d ON d.id = m.device_id AND d.is_deleted = FALSE
WHERE m.group_id = $1
ORDER BY d.id;

-- name: InsertDeviceGroup :one
INSERT INTO device_groups (
    id, name, description, created_at, created_by, is_dynamic, dynamic_query
)
VALUES (
    sqlc.arg(id), sqlc.arg(name), sqlc.arg(description), sqlc.arg(created_at),
    sqlc.arg(created_by), sqlc.arg(is_dynamic), sqlc.narg(dynamic_query)
)
RETURNING *;

-- name: RenameDeviceGroup :one
UPDATE device_groups SET name = sqlc.arg(new_name)
WHERE id = sqlc.arg(id) AND is_deleted = FALSE
RETURNING *;

-- name: UpdateDeviceGroupDescription :one
UPDATE device_groups SET description = sqlc.arg(description)
WHERE id = sqlc.arg(id) AND is_deleted = FALSE
RETURNING *;

-- name: UpdateDeviceGroupQuery :one
UPDATE device_groups
SET is_dynamic = sqlc.arg(is_dynamic), dynamic_query = sqlc.narg(dynamic_query)
WHERE id = sqlc.arg(id) AND is_deleted = FALSE
RETURNING *;

-- name: SetDeviceGroupSyncInterval :one
UPDATE device_groups SET sync_interval_minutes = sqlc.arg(sync_interval_minutes)
WHERE id = sqlc.arg(id) AND is_deleted = FALSE
RETURNING *;

-- name: SetDeviceGroupInventoryInterval :one
UPDATE device_groups SET inventory_interval_minutes = sqlc.arg(inventory_interval_minutes)
WHERE id = sqlc.arg(id) AND is_deleted = FALSE
RETURNING *;

-- name: SetDeviceGroupMaintenanceWindow :one
UPDATE device_groups SET maintenance_window = sqlc.arg(maintenance_window)
WHERE id = sqlc.arg(id) AND is_deleted = FALSE
RETURNING *;

-- name: AddDeviceGroupMember :execrows
INSERT INTO device_group_members (group_id, device_id, added_at)
SELECT sqlc.arg(group_id), sqlc.arg(device_id), sqlc.arg(added_at)
FROM device_groups g
JOIN devices d ON d.id = sqlc.arg(device_id) AND d.is_deleted = FALSE
WHERE g.id = sqlc.arg(group_id) AND g.is_deleted = FALSE AND g.is_dynamic = FALSE
ON CONFLICT (group_id, device_id) DO NOTHING;

-- name: RemoveDeviceGroupMember :execrows
DELETE FROM device_group_members m
USING device_groups g
WHERE m.group_id = sqlc.arg(group_id)
  AND m.device_id = sqlc.arg(device_id)
  AND g.id = m.group_id AND g.is_deleted = FALSE AND g.is_dynamic = FALSE;

-- name: DeleteDeviceGroupMembers :execrows
DELETE FROM device_group_members WHERE group_id = $1;

-- name: DeleteDeviceGroupAssignments :execrows
UPDATE assignments SET is_deleted = TRUE
WHERE target_type = 'device_group' AND target_id = $1 AND is_deleted = FALSE;

-- name: DeleteDeviceGroupUserRoleScopes :execrows
DELETE FROM user_roles WHERE scope_kind = 'device_group' AND scope_id = $1;

-- name: DeleteDeviceGroupUserGroupRoleScopes :execrows
DELETE FROM user_group_roles WHERE scope_kind = 'device_group' AND scope_id = $1;

-- name: SoftDeleteDeviceGroup :one
UPDATE device_groups SET is_deleted = TRUE
WHERE id = $1 AND is_deleted = FALSE
RETURNING *;
