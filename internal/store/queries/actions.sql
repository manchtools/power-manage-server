-- Actions queries (renamed from definitions)

-- name: GetActionByID :one
SELECT * FROM actions_projection
WHERE id = $1 AND is_deleted = FALSE;

-- name: GetActionByName :one
SELECT * FROM actions_projection
WHERE name = $1 AND is_deleted = FALSE;

-- name: ListActions :many
SELECT * FROM actions_projection
WHERE is_deleted = FALSE AND is_system = FALSE
  AND ($1::INTEGER = 0 OR action_type = $1)
ORDER BY created_at DESC
LIMIT $2 OFFSET $3;

-- name: CountActions :one
SELECT COUNT(*) FROM actions_projection
WHERE is_deleted = FALSE AND is_system = FALSE
  AND ($1::INTEGER = 0 OR action_type = $1);

-- name: GetActionNamesByIDs :many
SELECT id, name FROM actions_projection
WHERE id = ANY($1::TEXT[]);

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
  AND ($3::INTEGER = 0 OR action_type = $3)
  AND ($4::TEXT = '' OR EXISTS (
    SELECT 1 FROM actions_projection a WHERE a.id = executions_projection.action_id AND a.name ILIKE '%' || $4 || '%'
  ) OR EXISTS (
    SELECT 1 FROM devices_projection d WHERE d.id = executions_projection.device_id AND d.hostname ILIKE '%' || $4 || '%'
  ))
ORDER BY created_at DESC
LIMIT $5 OFFSET $6;

-- name: CountExecutions :one
SELECT COUNT(*) FROM executions_projection
WHERE ($1::TEXT = '' OR device_id = $1)
  AND ($2::TEXT = '' OR status = $2)
  AND ($3::INTEGER = 0 OR action_type = $3)
  AND ($4::TEXT = '' OR EXISTS (
    SELECT 1 FROM actions_projection a WHERE a.id = executions_projection.action_id AND a.name ILIKE '%' || $4 || '%'
  ) OR EXISTS (
    SELECT 1 FROM devices_projection d WHERE d.id = executions_projection.device_id AND d.hostname ILIKE '%' || $4 || '%'
  ));

-- name: ListPendingExecutionsForDevice :many
-- Include both 'pending' and 'dispatched' statuses, since dispatched executions
-- may need to be re-sent if the agent disconnected before receiving them
SELECT * FROM executions_projection
WHERE device_id = $1 AND status IN ('pending', 'dispatched')
ORDER BY created_at ASC;

-- name: ListStaleExecutions :many
-- Find dispatched executions that exceeded their timeout + grace period.
-- Only expires 'dispatched' status — 'pending' executions are left alone
-- because they represent assigned actions waiting for an offline device
-- to reconnect. dispatchPendingActions will dispatch them on reconnect.
SELECT id, device_id, timeout_seconds, status, created_at, dispatched_at
FROM executions_projection
WHERE status = 'dispatched'
  AND dispatched_at < NOW() - make_interval(secs => GREATEST(timeout_seconds, 300) + 300)
LIMIT 100;

-- name: ListRecentExecutionsForDevice :many
SELECT * FROM executions_projection
WHERE device_id = $1
ORDER BY created_at DESC
LIMIT $2;
