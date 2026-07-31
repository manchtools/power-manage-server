-- name: InsertDevice :one
INSERT INTO devices (id, hostname, agent_version, registered_at, last_seen_at)
VALUES ($1, $2, $3, $4, $4)
RETURNING *;

-- name: GetDevice :one
SELECT * FROM devices WHERE id = $1 AND is_deleted = FALSE;

-- name: UpdateDeviceHostname :execrows
UPDATE devices SET hostname = $2 WHERE id = $1 AND is_deleted = FALSE;

-- name: SoftDeleteDevice :execrows
UPDATE devices SET is_deleted = TRUE WHERE id = $1 AND is_deleted = FALSE;

-- name: CountDevices :one
SELECT COUNT(*) FROM devices WHERE is_deleted = FALSE;
