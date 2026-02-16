-- Device Inventory queries

-- name: UpsertDeviceInventory :exec
INSERT INTO device_inventory (device_id, table_name, rows, collected_at)
VALUES ($1, $2, $3, NOW())
ON CONFLICT (device_id, table_name)
DO UPDATE SET rows = $3, collected_at = NOW();

-- name: GetDeviceInventory :many
SELECT * FROM device_inventory
WHERE device_id = $1
ORDER BY table_name;

-- name: GetDeviceInventoryByTables :many
SELECT * FROM device_inventory
WHERE device_id = $1 AND table_name = ANY($2::TEXT[])
ORDER BY table_name;

-- name: DeleteDeviceInventory :exec
DELETE FROM device_inventory
WHERE device_id = $1;
