-- Group-scoped variables (manchtools/power-manage-server#195, design #59).
--
-- The `variables` JSONB column on device_groups_projection /
-- user_groups_projection holds an array of pm.v1.Variable-shaped
-- objects. The handler full-replaces the array on every Set / Delete
-- (the JSON authority lives in the handler, not in SQL — keeping per-
-- type validation in one place). The handler-side replacement also
-- means there's no projector contention on a partial-write race: the
-- whole column is overwritten or it isn't.
--
-- Step 1 (foundation): only the get/set primitives ship. Step 2 will
-- add the per-device list queries used by ListAvailableVariables.

-- name: GetDeviceGroupVariables :one
SELECT variables
FROM device_groups_projection
WHERE id = $1;

-- name: SetDeviceGroupVariables :exec
UPDATE device_groups_projection
SET variables = $2
WHERE id = $1;

-- name: GetUserGroupVariables :one
SELECT variables
FROM user_groups_projection
WHERE id = $1;

-- name: SetUserGroupVariables :exec
UPDATE user_groups_projection
SET variables = $2
WHERE id = $1;
