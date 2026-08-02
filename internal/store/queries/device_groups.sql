-- name: GetDeviceGroup :one
SELECT g.id, g.name, g.description, g.created_at, g.created_by,
       g.is_dynamic, g.dynamic_query, g.sync_interval_minutes,
       g.inventory_interval_minutes, g.maintenance_window,
       COUNT(d.id) AS live_member_count
FROM device_groups g
LEFT JOIN device_group_members m ON m.group_id = g.id
LEFT JOIN devices d ON d.id = m.device_id AND d.is_deleted = FALSE
WHERE g.id = ? AND g.is_deleted = FALSE
GROUP BY g.id;

-- name: ListDeviceGroups :many
SELECT g.id, g.name, g.description, g.created_at, g.created_by,
       g.is_dynamic, g.dynamic_query, g.sync_interval_minutes,
       g.inventory_interval_minutes, g.maintenance_window,
       COUNT(d.id) AS live_member_count
FROM device_groups g
LEFT JOIN device_group_members m ON m.group_id = g.id
LEFT JOIN devices d ON d.id = m.device_id AND d.is_deleted = FALSE
WHERE g.is_deleted = FALSE
  AND g.id > sqlc.arg(after_id)
  AND (
      NOT sqlc.arg(scope_restricted)
      OR g.id IN (SELECT CAST(value AS TEXT) FROM json_each(sqlc.arg(scope_group_ids_json)))
  )
GROUP BY g.id
ORDER BY g.id
LIMIT sqlc.arg(row_limit);

-- name: CountDeviceGroups :one
SELECT COUNT(*) FROM device_groups g
WHERE g.is_deleted = FALSE
  AND (
      NOT sqlc.arg(scope_restricted)
      OR g.id IN (SELECT CAST(value AS TEXT) FROM json_each(sqlc.arg(scope_group_ids_json)))
  );

-- name: ListDeviceGroupsForDevice :many
SELECT g.id, g.name, g.description, g.created_at, g.created_by,
       g.is_dynamic, g.dynamic_query, g.sync_interval_minutes,
       g.inventory_interval_minutes, g.maintenance_window,
       COUNT(live.id) AS live_member_count
FROM device_group_members requested
JOIN device_groups g ON g.id = requested.group_id AND g.is_deleted = FALSE
LEFT JOIN device_group_members members ON members.group_id = g.id
LEFT JOIN devices live ON live.id = members.device_id AND live.is_deleted = FALSE
WHERE requested.device_id = sqlc.arg(device_id)
  AND (
      NOT sqlc.arg(scope_restricted)
      OR g.id IN (SELECT CAST(value AS TEXT) FROM json_each(sqlc.arg(scope_group_ids_json)))
  )
GROUP BY g.id
ORDER BY g.id;

-- name: ListDeviceGroupMembers :many
SELECT d.id AS device_id, d.hostname, d.agent_version, d.last_seen_at
FROM device_group_members m
JOIN devices d ON d.id = m.device_id AND d.is_deleted = FALSE
WHERE m.group_id = ?
ORDER BY d.id;

-- name: ListDeviceGroupMemberIDs :many
SELECT m.device_id
FROM device_group_members m
WHERE m.group_id = ?
ORDER BY m.device_id;

-- name: GetDynamicDeviceGroupQueryForUpdate :one
SELECT is_dynamic, dynamic_query
FROM device_groups
WHERE id = ? AND is_deleted = FALSE;

-- name: ListDevicesForDynamicEvaluation :many
SELECT d.id, d.hostname,
       CAST(COALESCE((
           SELECT json_group_object(dl.key, dl.value)
           FROM device_labels dl
           WHERE dl.device_id = d.id
       ), '{}') AS BLOB) AS labels_json,
       CAST(COALESCE((
           SELECT json_group_object(di.table_name, json(di.rows))
           FROM device_inventory di
           WHERE di.device_id = d.id
       ), '{}') AS BLOB) AS inventory_json,
       CAST(COALESCE((
           SELECT json_group_array(name)
           FROM (
               SELECT dg.name
               FROM device_group_members memberships
               JOIN device_groups dg ON dg.id = memberships.group_id AND dg.is_deleted = FALSE
               WHERE memberships.device_id = d.id
               ORDER BY dg.name
           ) ordered_groups
       ), '[]') AS BLOB) AS group_names_json
FROM devices d
WHERE d.is_deleted = FALSE
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
DELETE FROM device_group_members
WHERE group_id = sqlc.arg(group_id)
  AND device_id = sqlc.arg(device_id)
  AND EXISTS (
      SELECT 1 FROM device_groups g
      WHERE g.id = device_group_members.group_id
        AND g.is_deleted = FALSE
        AND g.is_dynamic = FALSE
  );

-- name: AddDynamicDeviceGroupMembers :many
INSERT INTO device_group_members (group_id, device_id, added_at)
SELECT sqlc.arg(group_id), CAST(wanted.value AS TEXT), sqlc.arg(added_at)
FROM json_each(sqlc.arg(device_ids_json)) AS wanted
JOIN devices d ON d.id = CAST(wanted.value AS TEXT) AND d.is_deleted = FALSE
WHERE EXISTS (
    SELECT 1 FROM device_groups g
    WHERE g.id = sqlc.arg(group_id) AND g.is_deleted = FALSE AND g.is_dynamic = TRUE
)
ON CONFLICT (group_id, device_id) DO NOTHING
RETURNING device_id;

-- name: RemoveDynamicDeviceGroupMembers :many
DELETE FROM device_group_members
WHERE group_id = sqlc.arg(group_id)
  AND device_id IN (
      SELECT CAST(value AS TEXT) FROM json_each(sqlc.arg(device_ids_json))
  )
  AND EXISTS (
      SELECT 1 FROM device_groups g
      WHERE g.id = device_group_members.group_id
        AND g.is_deleted = FALSE
        AND g.is_dynamic = TRUE
  )
RETURNING device_id;

-- name: DeleteDeviceGroupMembers :execrows
DELETE FROM device_group_members WHERE group_id = ?;

-- name: DeleteDeviceGroupAssignments :execrows
UPDATE assignments SET is_deleted = TRUE
WHERE target_type = 'device_group' AND target_id = ? AND is_deleted = FALSE;

-- name: DeleteDeviceGroupUserRoleScopes :execrows
DELETE FROM user_roles WHERE scope_kind = 'device_group' AND scope_id = ?;

-- name: DeleteDeviceGroupUserGroupRoleScopes :execrows
DELETE FROM user_group_roles WHERE scope_kind = 'device_group' AND scope_id = ?;

-- name: SoftDeleteDeviceGroup :one
UPDATE device_groups SET is_deleted = TRUE
WHERE id = ? AND is_deleted = FALSE
RETURNING *;
