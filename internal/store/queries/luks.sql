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

-- name: MarkLuksKeysNotCurrent :exec
-- Step 1 of LuksKeyRotated projection. Flip the current row for the
-- (device_id, action_id, device_path) triple so the new key
-- (inserted by step 2) is the only is_current=TRUE row. The
-- `is_current = TRUE` predicate keeps the result identical (rows
-- already FALSE stay FALSE) but skips a write per historical row,
-- reducing write amplification on the hot path.
UPDATE luks_keys_projection
SET is_current = FALSE
WHERE device_id = $1
  AND action_id = $2
  AND device_path = $3
  AND is_current = TRUE;

-- name: InsertLuksKey :exec
-- Step 2 of LuksKeyRotated projection. Always inserts a new row;
-- step 3's trim keeps only the latest 3 by rotated_at.
INSERT INTO luks_keys_projection
    (device_id, action_id, device_path, passphrase, rotated_at, rotation_reason)
VALUES ($1, $2, $3, $4, $5, $6);

-- name: TrimLuksKeysToLast3 :exec
-- Step 3 of LuksKeyRotated projection. Keep only the latest 3 keys
-- per (device_id, action_id, device_path) — operational requirement
-- mirrors the LPS trim policy (retain previous in case rotation was
-- mid-flight; deeper history bloats encrypted-passphrase storage).
DELETE FROM luks_keys_projection AS k
WHERE k.device_id = $1
  AND k.action_id = $2
  AND k.device_path = $3
  AND k.id NOT IN (
      SELECT id FROM luks_keys_projection
      WHERE device_id = $1
        AND action_id = $2
        AND device_path = $3
      ORDER BY rotated_at DESC
      LIMIT 3
  );

-- name: UpdateLuksKeyRevocationStatus :exec
-- Used by the three revocation events (Dispatched, Revoked, Failed).
-- Updates ONLY the current row for the (device_id, action_id) pair
-- — the PL/pgSQL projector keyed on `is_current = TRUE` so older
-- rotated-out rows keep their historical revocation_status.
UPDATE luks_keys_projection
SET revocation_status = $3,
    revocation_error  = $4,
    revocation_at     = $5
WHERE device_id  = $1
  AND action_id  = $2
  AND is_current = TRUE;

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
