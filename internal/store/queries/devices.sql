-- name: InsertDevice :one
INSERT INTO devices (
    id, hostname, agent_version, agent_sealing_public_key,
    cert_fingerprint, cert_not_after, registered_at, last_seen_at,
    registration_token_id
)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
RETURNING *;

-- name: GetDevice :one
SELECT * FROM devices WHERE id = ? AND is_deleted = FALSE;

-- name: UpdateDeviceHostname :execrows
UPDATE devices SET hostname = ? WHERE id = ? AND is_deleted = FALSE;

-- name: RecordDeviceHello :execrows
UPDATE devices
SET hostname = sqlc.arg(hostname),
    agent_version = sqlc.arg(agent_version),
    last_seen_at = sqlc.arg(last_seen_at)
WHERE id = sqlc.arg(id) AND is_deleted = FALSE;

-- name: RecordDeviceHeartbeat :execrows
UPDATE devices
SET last_seen_at = sqlc.arg(last_seen_at)
WHERE id = sqlc.arg(device_id)
  AND is_deleted = FALSE
  AND (last_seen_at IS NULL OR last_seen_at < sqlc.arg(last_seen_at));

-- Advance the tracked certificate only when the presented fingerprint is
-- still current. This is the concurrency boundary for renewal: exactly one
-- caller can replace a given certificate.
-- name: ReplaceDeviceCertificate :one
UPDATE devices
SET cert_fingerprint = sqlc.arg(new_fingerprint),
    cert_not_after = sqlc.arg(new_not_after)
WHERE id = sqlc.arg(id)
  AND is_deleted = FALSE
  AND cert_fingerprint = sqlc.arg(old_fingerprint)
RETURNING *;

-- name: ListDevices :many
SELECT d.*
FROM devices d
WHERE d.is_deleted = FALSE
  AND d.id > sqlc.arg(after_id)
  AND (
      sqlc.narg(assigned_user_id) IS NULL
      OR EXISTS (
          SELECT 1 FROM device_assigned_users dau
          WHERE dau.device_id = d.id
            AND dau.user_id = sqlc.narg(assigned_user_id)
      )
      OR EXISTS (
          SELECT 1
          FROM device_assigned_groups dag
          JOIN user_groups ug ON ug.id = dag.group_id AND ug.is_deleted = FALSE
          JOIN user_group_members ugm ON ugm.group_id = dag.group_id
          WHERE dag.device_id = d.id
            AND ugm.user_id = sqlc.narg(assigned_user_id)
      )
  )
  AND (
      NOT sqlc.arg(scope_restricted)
      OR EXISTS (
          SELECT 1
          FROM device_group_members dgm
          JOIN device_groups dg ON dg.id = dgm.group_id AND dg.is_deleted = FALSE
          WHERE dgm.device_id = d.id
            AND dgm.group_id IN (SELECT CAST(value AS TEXT) FROM json_each(sqlc.arg(scope_group_ids_json)))
      )
  )
  AND NOT EXISTS (
      SELECT 1
      FROM json_each(sqlc.arg(label_filter)) wanted
      WHERE NOT EXISTS (
          SELECT 1 FROM device_labels dl
          WHERE dl.device_id = d.id
            AND dl.key = wanted.key
            AND dl.value = wanted.value
      )
  )
  AND (
      sqlc.arg(status_filter) = 0
      OR (sqlc.arg(status_filter) = 1 AND d.last_seen_at > sqlc.arg(online_since))
      OR (sqlc.arg(status_filter) = 2 AND (d.last_seen_at IS NULL OR d.last_seen_at <= sqlc.arg(online_since)))
  )
ORDER BY d.id
LIMIT sqlc.arg(row_limit);

-- name: CountDeviceViews :one
SELECT COUNT(*)
FROM devices d
WHERE d.is_deleted = FALSE
  AND (
      sqlc.narg(assigned_user_id) IS NULL
      OR EXISTS (
          SELECT 1 FROM device_assigned_users dau
          WHERE dau.device_id = d.id
            AND dau.user_id = sqlc.narg(assigned_user_id)
      )
      OR EXISTS (
          SELECT 1
          FROM device_assigned_groups dag
          JOIN user_groups ug ON ug.id = dag.group_id AND ug.is_deleted = FALSE
          JOIN user_group_members ugm ON ugm.group_id = dag.group_id
          WHERE dag.device_id = d.id
            AND ugm.user_id = sqlc.narg(assigned_user_id)
      )
  )
  AND (
      NOT sqlc.arg(scope_restricted)
      OR EXISTS (
          SELECT 1
          FROM device_group_members dgm
          JOIN device_groups dg ON dg.id = dgm.group_id AND dg.is_deleted = FALSE
          WHERE dgm.device_id = d.id
            AND dgm.group_id IN (SELECT CAST(value AS TEXT) FROM json_each(sqlc.arg(scope_group_ids_json)))
      )
  )
  AND NOT EXISTS (
      SELECT 1
      FROM json_each(sqlc.arg(label_filter)) wanted
      WHERE NOT EXISTS (
          SELECT 1 FROM device_labels dl
          WHERE dl.device_id = d.id
            AND dl.key = wanted.key
            AND dl.value = wanted.value
      )
  )
  AND (
      sqlc.arg(status_filter) = 0
      OR (sqlc.arg(status_filter) = 1 AND d.last_seen_at > sqlc.arg(online_since))
      OR (sqlc.arg(status_filter) = 2 AND (d.last_seen_at IS NULL OR d.last_seen_at <= sqlc.arg(online_since)))
  );

-- name: ListDeviceLabels :many
SELECT * FROM device_labels WHERE device_id = ? ORDER BY key;

-- name: ListDeviceLabelsBatch :many
SELECT * FROM device_labels
WHERE device_id IN (sqlc.slice(device_ids))
ORDER BY device_id, key;

-- name: SetDeviceLabel :execrows
INSERT INTO device_labels (device_id, key, value)
SELECT sqlc.arg(device_id), sqlc.arg(key), sqlc.arg(value)
WHERE EXISTS (SELECT 1 FROM devices WHERE id = sqlc.arg(device_id) AND is_deleted = FALSE)
ON CONFLICT (device_id, key) DO UPDATE SET value = EXCLUDED.value;

-- name: RemoveDeviceLabel :execrows
DELETE FROM device_labels WHERE device_id = ? AND key = ?;

-- name: ListDeviceAssignedUserIDs :many
SELECT user_id FROM device_assigned_users WHERE device_id = ? ORDER BY user_id;

-- name: ListDeviceAssignedUserIDsBatch :many
SELECT device_id, user_id FROM device_assigned_users
WHERE device_id IN (sqlc.slice(device_ids)) ORDER BY device_id, user_id;

-- name: ListDeviceAssignedGroupIDs :many
SELECT group_id FROM device_assigned_groups WHERE device_id = ? ORDER BY group_id;

-- name: ListDeviceAssignedGroupIDsBatch :many
SELECT device_id, group_id FROM device_assigned_groups
WHERE device_id IN (sqlc.slice(device_ids)) ORDER BY device_id, group_id;

-- name: ListDeviceAssignees :many
SELECT assignee_id, assignee_kind, assignee_name
FROM (
    SELECT dau.user_id AS assignee_id, 'user' AS assignee_kind,
           u.email AS assignee_name, 1 AS kind_order
    FROM device_assigned_users dau
    JOIN users u ON u.id = dau.user_id AND u.is_deleted = FALSE
    WHERE dau.device_id = sqlc.arg(device_id)
    UNION ALL
    SELECT dag.group_id AS assignee_id, 'user_group' AS assignee_kind,
           ug.name AS assignee_name, 2 AS kind_order
    FROM device_assigned_groups dag
    JOIN user_groups ug ON ug.id = dag.group_id AND ug.is_deleted = FALSE
    WHERE dag.device_id = sqlc.arg(device_id)
) assignees
ORDER BY kind_order, assignee_id;

-- name: IsDeviceAssignedToUser :one
SELECT EXISTS (
    SELECT 1
    FROM devices d
    WHERE d.id = sqlc.arg(device_id)
      AND d.is_deleted = FALSE
      AND (
          EXISTS (
              SELECT 1
              FROM device_assigned_users dau
              WHERE dau.device_id = d.id
                AND dau.user_id = sqlc.arg(user_id)
          )
          OR EXISTS (
              SELECT 1
              FROM device_assigned_groups dag
              JOIN user_groups ug ON ug.id = dag.group_id AND ug.is_deleted = FALSE
              JOIN user_group_members ugm ON ugm.group_id = dag.group_id
              WHERE dag.device_id = d.id
                AND ugm.user_id = sqlc.arg(user_id)
          )
      )
);

-- name: IsDeviceDirectlyAssignedToUser :one
SELECT EXISTS (
    SELECT 1
    FROM device_assigned_users dau
    JOIN devices d ON d.id = dau.device_id AND d.is_deleted = FALSE
    JOIN users u ON u.id = dau.user_id AND u.is_deleted = FALSE
    WHERE dau.device_id = sqlc.arg(device_id)
      AND dau.user_id = sqlc.arg(user_id)
);

-- name: ListLatestInventoryTimesForDevices :many
SELECT di.device_id, di.collected_at
FROM device_inventory di
WHERE di.device_id IN (sqlc.slice(device_ids))
  AND NOT EXISTS (
      SELECT 1 FROM device_inventory newer
      WHERE newer.device_id = di.device_id
        AND newer.collected_at > di.collected_at
  )
ORDER BY di.device_id;

-- name: ListGroupInventoryIntervalsForDevices :many
SELECT dgm.device_id, dg.inventory_interval_minutes
FROM device_group_members dgm
JOIN device_groups dg ON dg.id = dgm.group_id AND dg.is_deleted = FALSE
WHERE dgm.device_id IN (sqlc.slice(device_ids))
  AND dg.inventory_interval_minutes > 0
ORDER BY dgm.device_id, dg.inventory_interval_minutes;

-- name: ListDeviceInventory :many
SELECT table_name, rows, collected_at
FROM device_inventory
WHERE device_id = sqlc.arg(device_id)
  AND (
      sqlc.arg(all_table_names)
      OR table_name IN (sqlc.slice(table_names))
  )
ORDER BY table_name;

-- name: AssignDeviceUser :execrows
INSERT INTO device_assigned_users (device_id, user_id, assigned_at, assigned_by)
SELECT sqlc.arg(device_id), sqlc.arg(user_id), sqlc.arg(assigned_at), sqlc.arg(assigned_by)
WHERE EXISTS (SELECT 1 FROM devices d WHERE d.id = sqlc.arg(device_id) AND d.is_deleted = FALSE)
  AND EXISTS (SELECT 1 FROM users u WHERE u.id = sqlc.arg(user_id) AND u.is_deleted = FALSE)
ON CONFLICT (device_id, user_id) DO NOTHING;

-- name: AssignDeviceGroup :execrows
INSERT INTO device_assigned_groups (device_id, group_id, assigned_at, assigned_by)
SELECT sqlc.arg(device_id), sqlc.arg(group_id), sqlc.arg(assigned_at), sqlc.arg(assigned_by)
WHERE EXISTS (SELECT 1 FROM devices d WHERE d.id = sqlc.arg(device_id) AND d.is_deleted = FALSE)
  AND EXISTS (SELECT 1 FROM user_groups g WHERE g.id = sqlc.arg(group_id) AND g.is_deleted = FALSE)
ON CONFLICT (device_id, group_id) DO NOTHING;

-- name: UnassignDeviceUser :execrows
DELETE FROM device_assigned_users WHERE device_id = ? AND user_id = ?;

-- name: UnassignDeviceGroup :execrows
DELETE FROM device_assigned_groups WHERE device_id = ? AND group_id = ?;

-- name: SetDeviceSyncInterval :execrows
UPDATE devices SET sync_interval_minutes = sqlc.arg(minutes)
WHERE id = sqlc.arg(id) AND is_deleted = FALSE;

-- name: SetDeviceInventoryInterval :execrows
UPDATE devices SET inventory_interval_minutes = sqlc.arg(minutes)
WHERE id = sqlc.arg(id) AND is_deleted = FALSE;

-- name: ListDeviceGroupIDs :many
SELECT dgm.group_id
FROM device_group_members dgm
JOIN device_groups dg ON dg.id = dgm.group_id AND dg.is_deleted = FALSE
WHERE dgm.device_id = ?
ORDER BY dgm.group_id;

-- name: ListDeviceMaintenanceWindows :many
SELECT maintenance_window
FROM (
    SELECT dg.id AS group_id, dg.maintenance_window
    FROM device_group_members dgm
    JOIN device_groups dg ON dg.id = dgm.group_id AND dg.is_deleted = FALSE
    WHERE dgm.device_id = sqlc.arg(device_id)
      AND dg.maintenance_window <> '{}'
    UNION ALL
    SELECT ug.id AS group_id, ug.maintenance_window
    FROM device_assigned_groups dag
    JOIN user_groups ug ON ug.id = dag.group_id AND ug.is_deleted = FALSE
    WHERE dag.device_id = sqlc.arg(device_id)
      AND ug.maintenance_window <> '{}'
) windows
ORDER BY group_id;

-- name: SoftDeleteDevice :execrows
UPDATE devices SET is_deleted = TRUE WHERE id = ? AND is_deleted = FALSE;

-- name: CountDevices :one
SELECT COUNT(*) FROM devices WHERE is_deleted = FALSE;
