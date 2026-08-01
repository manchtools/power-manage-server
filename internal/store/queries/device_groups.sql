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

-- name: ListDeviceGroupMemberIDs :many
SELECT m.device_id
FROM device_group_members m
WHERE m.group_id = $1
ORDER BY m.device_id;

-- name: GetDynamicDeviceGroupQueryForUpdate :one
SELECT is_dynamic, dynamic_query
FROM device_groups
WHERE id = $1 AND is_deleted = FALSE
FOR UPDATE;

-- name: ListDevicesForDynamicEvaluation :many
SELECT d.id, d.hostname,
       convert_to(COALESCE((
           SELECT jsonb_object_agg(dl.key, dl.value)
           FROM device_labels dl
           WHERE dl.device_id = d.id
       ), '{}'::jsonb)::text, 'UTF8') AS labels_json,
       convert_to(COALESCE((
           SELECT jsonb_object_agg(di.table_name, di.rows)
           FROM device_inventory di
           WHERE di.device_id = d.id
       ), '{}'::jsonb)::text, 'UTF8') AS inventory_json,
       COALESCE((
           SELECT array_agg(dg.name ORDER BY dg.name)
           FROM device_group_members memberships
           JOIN device_groups dg ON dg.id = memberships.group_id AND dg.is_deleted = FALSE
           WHERE memberships.device_id = d.id
       ), ARRAY[]::text[])::text[] AS group_names
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
DELETE FROM device_group_members m
USING device_groups g
WHERE m.group_id = sqlc.arg(group_id)
  AND m.device_id = sqlc.arg(device_id)
  AND g.id = m.group_id AND g.is_deleted = FALSE AND g.is_dynamic = FALSE;

-- name: AddDynamicDeviceGroupMembers :many
INSERT INTO device_group_members (group_id, device_id, added_at)
SELECT sqlc.arg(group_id), wanted.device_id, sqlc.arg(added_at)
FROM unnest(sqlc.arg(device_ids)::text[]) AS wanted(device_id)
JOIN devices d ON d.id = wanted.device_id AND d.is_deleted = FALSE
WHERE EXISTS (
    SELECT 1 FROM device_groups g
    WHERE g.id = sqlc.arg(group_id) AND g.is_deleted = FALSE AND g.is_dynamic = TRUE
)
ON CONFLICT (group_id, device_id) DO NOTHING
RETURNING device_id;

-- name: RemoveDynamicDeviceGroupMembers :many
DELETE FROM device_group_members m
USING device_groups g
WHERE m.group_id = sqlc.arg(group_id)
  AND m.device_id = ANY(sqlc.arg(device_ids)::text[])
  AND g.id = m.group_id AND g.is_deleted = FALSE AND g.is_dynamic = TRUE
RETURNING m.device_id;

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
