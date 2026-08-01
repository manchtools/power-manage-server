-- name: InsertDevice :one
INSERT INTO devices (
    id, hostname, agent_version, agent_sealing_public_key,
    cert_fingerprint, cert_not_after, registered_at, last_seen_at,
    registration_token_id
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
RETURNING *;

-- name: GetDevice :one
SELECT * FROM devices WHERE id = $1 AND is_deleted = FALSE;

-- name: UpdateDeviceHostname :execrows
UPDATE devices SET hostname = $2 WHERE id = $1 AND is_deleted = FALSE;

-- name: ListDevices :many
SELECT d.*
FROM devices d
WHERE d.is_deleted = FALSE
  AND d.id > sqlc.arg(after_id)
  AND (
      sqlc.narg(assigned_user_id)::text IS NULL
      OR EXISTS (
          SELECT 1 FROM device_assigned_users dau
          WHERE dau.device_id = d.id
            AND dau.user_id = sqlc.narg(assigned_user_id)::text
      )
      OR EXISTS (
          SELECT 1
          FROM device_assigned_groups dag
          JOIN user_groups ug ON ug.id = dag.group_id AND ug.is_deleted = FALSE
          JOIN user_group_members ugm ON ugm.group_id = dag.group_id
          WHERE dag.device_id = d.id
            AND ugm.user_id = sqlc.narg(assigned_user_id)::text
      )
  )
  AND (
      NOT sqlc.arg(scope_restricted)::boolean
      OR EXISTS (
          SELECT 1
          FROM device_group_members dgm
          JOIN device_groups dg ON dg.id = dgm.group_id AND dg.is_deleted = FALSE
          WHERE dgm.device_id = d.id
            AND dgm.group_id = ANY(sqlc.arg(scope_group_ids)::text[])
      )
  )
  AND NOT EXISTS (
      SELECT 1
      FROM jsonb_each_text(sqlc.arg(label_filter)::jsonb) wanted
      WHERE NOT EXISTS (
          SELECT 1 FROM device_labels dl
          WHERE dl.device_id = d.id
            AND dl.key = wanted.key
            AND dl.value = wanted.value
      )
  )
  AND (
      sqlc.arg(status_filter)::integer = 0
      OR (sqlc.arg(status_filter)::integer = 1 AND d.last_seen_at > sqlc.arg(online_since))
      OR (sqlc.arg(status_filter)::integer = 2 AND (d.last_seen_at IS NULL OR d.last_seen_at <= sqlc.arg(online_since)))
  )
ORDER BY d.id
LIMIT sqlc.arg(row_limit);

-- name: CountDeviceViews :one
SELECT COUNT(*)
FROM devices d
WHERE d.is_deleted = FALSE
  AND (
      sqlc.narg(assigned_user_id)::text IS NULL
      OR EXISTS (
          SELECT 1 FROM device_assigned_users dau
          WHERE dau.device_id = d.id
            AND dau.user_id = sqlc.narg(assigned_user_id)::text
      )
      OR EXISTS (
          SELECT 1
          FROM device_assigned_groups dag
          JOIN user_groups ug ON ug.id = dag.group_id AND ug.is_deleted = FALSE
          JOIN user_group_members ugm ON ugm.group_id = dag.group_id
          WHERE dag.device_id = d.id
            AND ugm.user_id = sqlc.narg(assigned_user_id)::text
      )
  )
  AND (
      NOT sqlc.arg(scope_restricted)::boolean
      OR EXISTS (
          SELECT 1
          FROM device_group_members dgm
          JOIN device_groups dg ON dg.id = dgm.group_id AND dg.is_deleted = FALSE
          WHERE dgm.device_id = d.id
            AND dgm.group_id = ANY(sqlc.arg(scope_group_ids)::text[])
      )
  )
  AND NOT EXISTS (
      SELECT 1
      FROM jsonb_each_text(sqlc.arg(label_filter)::jsonb) wanted
      WHERE NOT EXISTS (
          SELECT 1 FROM device_labels dl
          WHERE dl.device_id = d.id
            AND dl.key = wanted.key
            AND dl.value = wanted.value
      )
  )
  AND (
      sqlc.arg(status_filter)::integer = 0
      OR (sqlc.arg(status_filter)::integer = 1 AND d.last_seen_at > sqlc.arg(online_since))
      OR (sqlc.arg(status_filter)::integer = 2 AND (d.last_seen_at IS NULL OR d.last_seen_at <= sqlc.arg(online_since)))
  );

-- name: ListDeviceLabels :many
SELECT * FROM device_labels WHERE device_id = $1 ORDER BY key;

-- name: ListDeviceLabelsBatch :many
SELECT * FROM device_labels WHERE device_id = ANY($1::text[]) ORDER BY device_id, key;

-- name: SetDeviceLabel :execrows
INSERT INTO device_labels (device_id, key, value)
SELECT $1, $2, $3
WHERE EXISTS (SELECT 1 FROM devices WHERE id = $1 AND is_deleted = FALSE)
ON CONFLICT (device_id, key) DO UPDATE SET value = EXCLUDED.value;

-- name: RemoveDeviceLabel :execrows
DELETE FROM device_labels WHERE device_id = $1 AND key = $2;

-- name: ListDeviceAssignedUserIDs :many
SELECT user_id FROM device_assigned_users WHERE device_id = $1 ORDER BY user_id;

-- name: ListDeviceAssignedUserIDsBatch :many
SELECT device_id, user_id FROM device_assigned_users
WHERE device_id = ANY($1::text[]) ORDER BY device_id, user_id;

-- name: ListDeviceAssignedGroupIDs :many
SELECT group_id FROM device_assigned_groups WHERE device_id = $1 ORDER BY group_id;

-- name: ListDeviceAssignedGroupIDsBatch :many
SELECT device_id, group_id FROM device_assigned_groups
WHERE device_id = ANY($1::text[]) ORDER BY device_id, group_id;

-- name: AssignDeviceUser :execrows
INSERT INTO device_assigned_users (device_id, user_id, assigned_at, assigned_by)
SELECT $1, $2, $3, $4
WHERE EXISTS (SELECT 1 FROM devices WHERE id = $1 AND is_deleted = FALSE)
  AND EXISTS (SELECT 1 FROM users WHERE id = $2 AND is_deleted = FALSE)
ON CONFLICT (device_id, user_id) DO NOTHING;

-- name: AssignDeviceGroup :execrows
INSERT INTO device_assigned_groups (device_id, group_id, assigned_at, assigned_by)
SELECT $1, $2, $3, $4
WHERE EXISTS (SELECT 1 FROM devices WHERE id = $1 AND is_deleted = FALSE)
  AND EXISTS (SELECT 1 FROM user_groups WHERE id = $2 AND is_deleted = FALSE)
ON CONFLICT (device_id, group_id) DO NOTHING;

-- name: UnassignDeviceUser :execrows
DELETE FROM device_assigned_users WHERE device_id = $1 AND user_id = $2;

-- name: UnassignDeviceGroup :execrows
DELETE FROM device_assigned_groups WHERE device_id = $1 AND group_id = $2;

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
WHERE dgm.device_id = $1
ORDER BY dgm.group_id;

-- name: SoftDeleteDevice :execrows
UPDATE devices SET is_deleted = TRUE WHERE id = $1 AND is_deleted = FALSE;

-- name: CountDevices :one
SELECT COUNT(*) FROM devices WHERE is_deleted = FALSE;
