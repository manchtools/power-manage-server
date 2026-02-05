-- name: GetDeviceByID :one
SELECT * FROM devices_projection
WHERE id = $1 AND is_deleted = FALSE;

-- name: GetDeviceByFingerprint :one
SELECT * FROM devices_projection
WHERE cert_fingerprint = $1 AND is_deleted = FALSE;

-- name: ListDevices :many
SELECT * FROM devices_projection
WHERE is_deleted = FALSE
ORDER BY last_seen_at DESC
LIMIT $1 OFFSET $2;

-- name: ListDevicesOnline :many
SELECT * FROM devices_projection
WHERE is_deleted = FALSE
  AND last_seen_at > NOW() - INTERVAL '5 minutes'
ORDER BY last_seen_at DESC
LIMIT $1 OFFSET $2;

-- name: ListDevicesOffline :many
SELECT * FROM devices_projection
WHERE is_deleted = FALSE
  AND last_seen_at <= NOW() - INTERVAL '5 minutes'
ORDER BY last_seen_at DESC
LIMIT $1 OFFSET $2;

-- name: CountDevices :one
SELECT COUNT(*) FROM devices_projection
WHERE is_deleted = FALSE;

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

-- name: ListDevicesByAssignedUser :many
SELECT * FROM devices_projection
WHERE is_deleted = FALSE
  AND assigned_user_id = $1
ORDER BY last_seen_at DESC
LIMIT $2 OFFSET $3;

-- name: CountDevicesByAssignedUser :one
SELECT COUNT(*) FROM devices_projection
WHERE is_deleted = FALSE
  AND assigned_user_id = $1;

-- name: ListDevicesByAssignedUserOnline :many
SELECT * FROM devices_projection
WHERE is_deleted = FALSE
  AND assigned_user_id = $1
  AND last_seen_at > NOW() - INTERVAL '5 minutes'
ORDER BY last_seen_at DESC
LIMIT $2 OFFSET $3;

-- name: ListDevicesByAssignedUserOffline :many
SELECT * FROM devices_projection
WHERE is_deleted = FALSE
  AND assigned_user_id = $1
  AND last_seen_at <= NOW() - INTERVAL '5 minutes'
ORDER BY last_seen_at DESC
LIMIT $2 OFFSET $3;

-- name: GetDeviceByIDForUser :one
SELECT * FROM devices_projection
WHERE id = $1 AND is_deleted = FALSE AND assigned_user_id = $2;

-- name: GetDeviceSyncInterval :one
SELECT get_device_sync_interval($1::TEXT) AS sync_interval_minutes;
