-- Device Groups queries

-- name: GetDeviceGroupByID :one
SELECT * FROM device_groups_projection
WHERE id = $1 AND is_deleted = FALSE;

-- name: GetDeviceGroupByName :one
SELECT * FROM device_groups_projection
WHERE name = $1 AND is_deleted = FALSE;

-- name: ListDeviceGroups :many
SELECT * FROM device_groups_projection
WHERE is_deleted = FALSE
ORDER BY created_at DESC
LIMIT $1 OFFSET $2;

-- name: CountDeviceGroups :one
SELECT COUNT(*) FROM device_groups_projection
WHERE is_deleted = FALSE;

-- Device Group Members queries

-- name: ListDeviceGroupMembers :many
SELECT * FROM device_group_members_projection
WHERE group_id = $1
ORDER BY added_at ASC;

-- name: GetDeviceGroupMember :one
SELECT * FROM device_group_members_projection
WHERE group_id = $1 AND device_id = $2;

-- name: ListDevicesInGroup :many
SELECT d.* FROM devices_projection d
JOIN device_group_members_projection m ON d.id = m.device_id
WHERE m.group_id = $1 AND d.is_deleted = FALSE
ORDER BY d.hostname ASC;

-- name: ListGroupsForDevice :many
SELECT g.* FROM device_groups_projection g
JOIN device_group_members_projection m ON g.id = m.group_id
WHERE m.device_id = $1 AND g.is_deleted = FALSE
ORDER BY g.name ASC;

-- Dynamic Group queries

-- name: ListDynamicDeviceGroups :many
SELECT * FROM device_groups_projection
WHERE is_dynamic = TRUE AND is_deleted = FALSE
ORDER BY created_at DESC;

-- name: GetDynamicGroupsNeedingEvaluation :many
SELECT g.* FROM device_groups_projection g
JOIN dynamic_group_evaluation_queue q ON g.id = q.group_id
WHERE g.is_deleted = FALSE
ORDER BY q.queued_at ASC
LIMIT $1;

-- name: ValidateDynamicQuery :one
SELECT COALESCE(validate_dynamic_query($1), '')::TEXT AS error_message;

-- name: EvaluateDynamicGroup :exec
SELECT evaluate_dynamic_group($1);

-- name: EvaluateQueuedDynamicGroups :one
SELECT evaluate_queued_dynamic_groups() AS evaluated_count;

-- name: CountMatchingDevicesForQuery :one
SELECT COUNT(*) FROM devices_projection
WHERE is_deleted = FALSE
AND evaluate_dynamic_query_v2(id, labels, $1) = TRUE;
