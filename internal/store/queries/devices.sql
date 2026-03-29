-- name: GetDeviceByID :one
SELECT * FROM devices_projection
WHERE id = $1 AND is_deleted = FALSE
  AND (sqlc.narg('filter_user_id')::TEXT IS NULL
    OR EXISTS (SELECT 1 FROM device_assigned_users_projection dau WHERE dau.device_id = devices_projection.id AND dau.user_id = sqlc.narg('filter_user_id'))
    OR EXISTS (SELECT 1 FROM device_assigned_groups_projection dag JOIN user_group_members_projection ugm ON ugm.group_id = dag.group_id WHERE dag.device_id = devices_projection.id AND ugm.user_id = sqlc.narg('filter_user_id'))
  );

-- name: IsDeviceDeleted :one
SELECT is_deleted FROM devices_projection WHERE id = $1;

-- name: GetDeviceByFingerprint :one
SELECT * FROM devices_projection
WHERE cert_fingerprint = $1 AND is_deleted = FALSE;

-- name: ListDevices :many
SELECT * FROM devices_projection
WHERE is_deleted = FALSE
  AND (sqlc.narg('filter_user_id')::TEXT IS NULL
    OR EXISTS (SELECT 1 FROM device_assigned_users_projection dau WHERE dau.device_id = devices_projection.id AND dau.user_id = sqlc.narg('filter_user_id'))
    OR EXISTS (SELECT 1 FROM device_assigned_groups_projection dag JOIN user_group_members_projection ugm ON ugm.group_id = dag.group_id WHERE dag.device_id = devices_projection.id AND ugm.user_id = sqlc.narg('filter_user_id'))
  )
ORDER BY last_seen_at DESC
LIMIT $1 OFFSET $2;

-- name: ListDevicesOnline :many
SELECT * FROM devices_projection
WHERE is_deleted = FALSE
  AND last_seen_at > NOW() - INTERVAL '5 minutes'
  AND (sqlc.narg('filter_user_id')::TEXT IS NULL
    OR EXISTS (SELECT 1 FROM device_assigned_users_projection dau WHERE dau.device_id = devices_projection.id AND dau.user_id = sqlc.narg('filter_user_id'))
    OR EXISTS (SELECT 1 FROM device_assigned_groups_projection dag JOIN user_group_members_projection ugm ON ugm.group_id = dag.group_id WHERE dag.device_id = devices_projection.id AND ugm.user_id = sqlc.narg('filter_user_id'))
  )
ORDER BY last_seen_at DESC
LIMIT $1 OFFSET $2;

-- name: ListDevicesOffline :many
SELECT * FROM devices_projection
WHERE is_deleted = FALSE
  AND last_seen_at <= NOW() - INTERVAL '5 minutes'
  AND (sqlc.narg('filter_user_id')::TEXT IS NULL
    OR EXISTS (SELECT 1 FROM device_assigned_users_projection dau WHERE dau.device_id = devices_projection.id AND dau.user_id = sqlc.narg('filter_user_id'))
    OR EXISTS (SELECT 1 FROM device_assigned_groups_projection dag JOIN user_group_members_projection ugm ON ugm.group_id = dag.group_id WHERE dag.device_id = devices_projection.id AND ugm.user_id = sqlc.narg('filter_user_id'))
  )
ORDER BY last_seen_at DESC
LIMIT $1 OFFSET $2;

-- name: CountDevices :one
SELECT COUNT(*) FROM devices_projection
WHERE is_deleted = FALSE
  AND (sqlc.narg('filter_user_id')::TEXT IS NULL
    OR EXISTS (SELECT 1 FROM device_assigned_users_projection dau WHERE dau.device_id = devices_projection.id AND dau.user_id = sqlc.narg('filter_user_id'))
    OR EXISTS (SELECT 1 FROM device_assigned_groups_projection dag JOIN user_group_members_projection ugm ON ugm.group_id = dag.group_id WHERE dag.device_id = devices_projection.id AND ugm.user_id = sqlc.narg('filter_user_id'))
  );

-- name: CountDevicesOnline :one
SELECT COUNT(*) FROM devices_projection
WHERE is_deleted = FALSE
  AND last_seen_at > NOW() - INTERVAL '5 minutes'
  AND (sqlc.narg('filter_user_id')::TEXT IS NULL
    OR EXISTS (SELECT 1 FROM device_assigned_users_projection dau WHERE dau.device_id = devices_projection.id AND dau.user_id = sqlc.narg('filter_user_id'))
    OR EXISTS (SELECT 1 FROM device_assigned_groups_projection dag JOIN user_group_members_projection ugm ON ugm.group_id = dag.group_id WHERE dag.device_id = devices_projection.id AND ugm.user_id = sqlc.narg('filter_user_id'))
  );

-- name: CountDevicesOffline :one
SELECT COUNT(*) FROM devices_projection
WHERE is_deleted = FALSE
  AND last_seen_at <= NOW() - INTERVAL '5 minutes'
  AND (sqlc.narg('filter_user_id')::TEXT IS NULL
    OR EXISTS (SELECT 1 FROM device_assigned_users_projection dau WHERE dau.device_id = devices_projection.id AND dau.user_id = sqlc.narg('filter_user_id'))
    OR EXISTS (SELECT 1 FROM device_assigned_groups_projection dag JOIN user_group_members_projection ugm ON ugm.group_id = dag.group_id WHERE dag.device_id = devices_projection.id AND ugm.user_id = sqlc.narg('filter_user_id'))
  );

-- name: ListDeviceAssignedUserIDsBatch :many
SELECT device_id, user_id FROM device_assigned_users_projection WHERE device_id = ANY(@device_ids::text[]);

-- name: ListDeviceAssignedGroupIDsBatch :many
SELECT device_id, group_id FROM device_assigned_groups_projection WHERE device_id = ANY(@device_ids::text[]);

-- name: GetDevicesWithLabel :many
SELECT * FROM devices_projection
WHERE is_deleted = FALSE
  AND labels->>$1 = $2
ORDER BY last_seen_at DESC
LIMIT $3 OFFSET $4;

-- name: GetDeviceSyncInterval :one
SELECT get_device_sync_interval($1::TEXT) AS sync_interval_minutes;

-- name: ListDeviceAssignedUsers :many
SELECT dau.user_id, u.email AS user_email, dau.assigned_at
FROM device_assigned_users_projection dau
JOIN users_projection u ON u.id = dau.user_id AND u.is_deleted = FALSE
WHERE dau.device_id = $1
ORDER BY dau.assigned_at;

-- name: ListDeviceAssignedGroups :many
SELECT dag.group_id, ug.name AS group_name, dag.assigned_at
FROM device_assigned_groups_projection dag
JOIN user_groups_projection ug ON ug.id = dag.group_id AND ug.is_deleted = FALSE
WHERE dag.device_id = $1
ORDER BY dag.assigned_at;

-- name: ListDeviceAssignedUserIDs :many
SELECT user_id FROM device_assigned_users_projection WHERE device_id = $1;

-- name: ListDeviceAssignedGroupIDs :many
SELECT group_id FROM device_assigned_groups_projection WHERE device_id = $1;
