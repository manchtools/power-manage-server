-- Actions queries (renamed from definitions)

-- name: GetActionByID :one
SELECT * FROM actions_projection
WHERE id = $1 AND is_deleted = FALSE;

-- name: GetActionByName :one
SELECT * FROM actions_projection
WHERE name = $1 AND is_deleted = FALSE;

-- name: ListActions :many
SELECT * FROM actions_projection
WHERE is_deleted = FALSE
  AND ($1::INTEGER = 0 OR action_type = $1)
ORDER BY created_at DESC
LIMIT $2 OFFSET $3;

-- name: CountActions :one
SELECT COUNT(*) FROM actions_projection
WHERE is_deleted = FALSE
  AND ($1::INTEGER = 0 OR action_type = $1);

-- name: UpdateActionSignature :exec
UPDATE actions_projection
SET signature = $2, params_canonical = $3
WHERE id = $1;

-- Executions queries

-- name: GetExecutionByID :one
SELECT * FROM executions_projection
WHERE id = $1;

-- name: ListExecutions :many
SELECT * FROM executions_projection
WHERE ($1::TEXT = '' OR device_id = $1)
  AND ($2::TEXT = '' OR status = $2)
ORDER BY created_at DESC
LIMIT $3 OFFSET $4;

-- name: CountExecutions :one
SELECT COUNT(*) FROM executions_projection
WHERE ($1::TEXT = '' OR device_id = $1)
  AND ($2::TEXT = '' OR status = $2);

-- name: ListPendingExecutionsForDevice :many
-- Include both 'pending' and 'dispatched' statuses, since dispatched executions
-- may need to be re-sent if the agent disconnected before receiving them
SELECT * FROM executions_projection
WHERE device_id = $1 AND status IN ('pending', 'dispatched')
ORDER BY created_at ASC;

-- name: ListRecentExecutionsForDevice :many
SELECT * FROM executions_projection
WHERE device_id = $1
ORDER BY created_at DESC
LIMIT $2;
