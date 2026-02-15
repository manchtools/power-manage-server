-- name: GetCurrentLuksKeys :many
SELECT * FROM luks_keys_projection
WHERE device_id = $1 AND is_current = TRUE
ORDER BY rotated_at DESC;

-- name: GetCurrentLuksKeyForAction :one
SELECT * FROM luks_keys_projection
WHERE device_id = $1 AND action_id = $2 AND is_current = TRUE
ORDER BY rotated_at DESC
LIMIT 1;

-- name: GetLuksKeyHistory :many
SELECT * FROM luks_keys_projection
WHERE device_id = $1 AND is_current = FALSE
ORDER BY rotated_at DESC
LIMIT 20;

-- name: DeleteLuksKeysByAction :exec
DELETE FROM luks_keys_projection WHERE action_id = $1;

-- name: CreateLuksToken :one
INSERT INTO luks_tokens (device_id, action_id, token, min_length, complexity, expires_at)
VALUES ($1, $2, $3, $4, $5, NOW() + INTERVAL '15 minutes')
RETURNING *;

-- name: ValidateAndConsumeLuksToken :one
UPDATE luks_tokens
SET used = TRUE
WHERE token = $1
  AND device_id = $2
  AND NOT used
  AND expires_at > NOW()
RETURNING *;
