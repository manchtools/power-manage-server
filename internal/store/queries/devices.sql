-- name: GetDeviceByID :one
SELECT * FROM devices_projection
WHERE id = $1 AND is_deleted = FALSE
  AND (sqlc.narg('filter_user_id')::TEXT IS NULL OR assigned_user_id = sqlc.narg('filter_user_id'));

-- name: GetDeviceByFingerprint :one
SELECT * FROM devices_projection
WHERE cert_fingerprint = $1 AND is_deleted = FALSE;

-- name: ListDevices :many
SELECT * FROM devices_projection
WHERE is_deleted = FALSE
  AND (sqlc.narg('filter_user_id')::TEXT IS NULL OR assigned_user_id = sqlc.narg('filter_user_id'))
ORDER BY last_seen_at DESC
LIMIT $1 OFFSET $2;

-- name: ListDevicesOnline :many
SELECT * FROM devices_projection
WHERE is_deleted = FALSE
  AND last_seen_at > NOW() - INTERVAL '5 minutes'
  AND (sqlc.narg('filter_user_id')::TEXT IS NULL OR assigned_user_id = sqlc.narg('filter_user_id'))
ORDER BY last_seen_at DESC
LIMIT $1 OFFSET $2;

-- name: ListDevicesOffline :many
SELECT * FROM devices_projection
WHERE is_deleted = FALSE
  AND last_seen_at <= NOW() - INTERVAL '5 minutes'
  AND (sqlc.narg('filter_user_id')::TEXT IS NULL OR assigned_user_id = sqlc.narg('filter_user_id'))
ORDER BY last_seen_at DESC
LIMIT $1 OFFSET $2;

-- name: CountDevices :one
SELECT COUNT(*) FROM devices_projection
WHERE is_deleted = FALSE
  AND (sqlc.narg('filter_user_id')::TEXT IS NULL OR assigned_user_id = sqlc.narg('filter_user_id'));

-- name: CountDevicesOnline :one
SELECT COUNT(*) FROM devices_projection
WHERE is_deleted = FALSE
  AND last_seen_at > NOW() - INTERVAL '5 minutes';

-- name: GetDevicesWithLabel :many
SELECT * FROM devices_projection
WHERE is_deleted = FALSE
  AND labels->>$1 = $2
ORDER BY last_seen_at DESC
LIMIT $3 OFFSET $4;

-- name: GetDeviceSyncInterval :one
SELECT get_device_sync_interval($1::TEXT) AS sync_interval_minutes;
