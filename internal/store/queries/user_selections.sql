-- User selections queries

-- name: GetUserSelection :one
SELECT * FROM user_selections_projection
WHERE device_id = $1 AND source_type = $2 AND source_id = $3;

-- name: ListUserSelectionsForDevice :many
SELECT * FROM user_selections_projection
WHERE device_id = $1
ORDER BY updated_at DESC;

-- List all available-mode assignments targeting a device (directly, via device groups,
-- via the device's assigned users, or via their user groups).
-- Used to build the catalog of items a user can select/deselect.
-- name: ListAvailableAssignmentsForDevice :many
WITH device_owners AS (
  SELECT dau.user_id FROM device_assigned_users_projection dau WHERE dau.device_id = $1
  UNION
  SELECT ugm.user_id FROM device_assigned_groups_projection dag
  JOIN user_group_members_projection ugm ON ugm.group_id = dag.group_id
  WHERE dag.device_id = $1
),
owner_groups AS (
  SELECT DISTINCT ugm.group_id FROM user_group_members_projection ugm
  JOIN user_groups_projection ug ON ug.id = ugm.group_id AND ug.is_deleted = FALSE
  WHERE ugm.user_id IN (SELECT user_id FROM device_owners)
)
SELECT DISTINCT asn.* FROM assignments_projection asn
WHERE asn.mode = 1 AND asn.is_deleted = FALSE
  AND (
    (asn.target_type = 'device' AND asn.target_id = $1)
    OR (asn.target_type = 'device_group' AND asn.target_id IN (
      SELECT m.group_id FROM device_group_members_projection m WHERE m.device_id = $1
    ))
    OR (asn.target_type = 'user' AND asn.target_id IN (SELECT user_id FROM device_owners))
    OR (asn.target_type = 'user_group' AND asn.target_id IN (SELECT group_id FROM owner_groups))
  )
ORDER BY asn.created_at DESC;

-- name: UpsertUserSelectionProjection :exec
-- UserSelectionChanged handler. ON CONFLICT (device_id, source_type,
-- source_id) DO UPDATE matches the PL/pgSQL projector — repeated
-- selection toggles refresh the row in place. Stale-replay guard
-- on the conflict-update path: only overwrite if the incoming
-- projection_version is newer (matching the WHERE-guard pattern
-- established for other ports).
INSERT INTO user_selections_projection (
    id, device_id, source_type, source_id, selected,
    updated_at, created_by, projection_version
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (device_id, source_type, source_id) DO UPDATE SET
    selected = EXCLUDED.selected,
    updated_at = EXCLUDED.updated_at,
    projection_version = EXCLUDED.projection_version
WHERE user_selections_projection.projection_version < EXCLUDED.projection_version;
