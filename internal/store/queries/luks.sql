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

-- GetLuksRevocationStreamID looks up the luks_key event-stream ID that
-- was minted when api/device_handler.go appended the
-- LuksDeviceKeyRevocationRequested event for this (device, action).
-- The inbox worker uses it to append the final Revoked / Failed event
-- to the SAME stream so the three-phase projection stitches together.
-- Returns the most recent request if somehow there are multiple (there
-- should only ever be one; LIMIT 1 is belt-and-braces).
--
-- name: GetLuksRevocationStreamID :one
SELECT stream_id
FROM events
WHERE stream_type = 'luks_key'
  AND event_type IN ('LuksDeviceKeyRevocationRequested', 'LuksDeviceKeyRevocationDispatched')
  AND data->>'device_id' = sqlc.arg(device_id)::text
  AND data->>'action_id' = sqlc.arg(action_id)::text
ORDER BY sequence_num DESC
LIMIT 1;
