-- User selections queries

-- name: GetUserSelection :one
SELECT * FROM user_selections_projection
WHERE device_id = $1 AND source_type = $2 AND source_id = $3;

-- name: ListUserSelectionsForDevice :many
SELECT * FROM user_selections_projection
WHERE device_id = $1
ORDER BY updated_at DESC;

-- List all available-mode assignments targeting a device (directly or via groups)
-- Used to build the catalog of items a user can select/deselect
-- name: ListAvailableAssignmentsForDevice :many
SELECT DISTINCT asn.* FROM assignments_projection asn
WHERE asn.mode = 1 AND asn.is_deleted = FALSE
  AND (
    (asn.target_type = 'device' AND asn.target_id = $1)
    OR (asn.target_type = 'device_group' AND asn.target_id IN (
      SELECT m.group_id FROM device_group_members_projection m WHERE m.device_id = $1
    ))
  )
ORDER BY asn.created_at DESC;
