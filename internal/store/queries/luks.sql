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

-- name: MarkLuksKeysNotCurrent :execrows
-- Step 1 of LuksKeyRotated projection. Flip the current row for the
-- (device_id, action_id, device_path) triple so the new key
-- (inserted by step 2) is the only is_current=TRUE row. The
-- `is_current = TRUE` predicate keeps the result identical (rows
-- already FALSE stay FALSE) but skips a write per historical row,
-- reducing write amplification on the hot path.
--
-- The projection_version guard rejects stale-replay re-deliveries:
-- a re-fired old event whose sequence_num is <= the last applied
-- version for any matching row gets 0 rows-affected, and the
-- listener short-circuits the cascade insert + trim. Without the
-- guard, a reconciler-driven re-delivery of an old LuksKeyRotated
-- would re-mark the latest (real-current) row as not_current and
-- insert a stale duplicate underneath it. Audit N007 (mirrors
-- LPS audit F020/F021).
UPDATE luks_keys_projection
SET is_current = FALSE,
    projection_version = sqlc.arg('projection_version')
WHERE device_id = $1
  AND action_id = $2
  AND device_path = $3
  AND is_current = TRUE
  AND projection_version < sqlc.arg('projection_version');

-- name: InsertLuksKey :exec
-- Step 2 of LuksKeyRotated projection. Inserts the new row only when
-- the listener confirmed via MarkLuksKeysNotCurrent's :execrows that
-- this is NOT a stale replay. The listener short-circuits when n==0
-- and a sibling row already exists, so this insert never runs against
-- a stale event. projection_version on the new row is the same
-- sequence_num that just guarded step 1.
INSERT INTO luks_keys_projection
    (device_id, action_id, device_path, passphrase, rotated_at, rotation_reason, projection_version)
VALUES ($1, $2, $3, $4, $5, $6, $7);

-- name: LuksKeyExistsForDeviceActionPath :one
-- Companion to the asymmetric stale-replay guard in
-- MarkLuksKeysNotCurrent. Used by the listener to disambiguate the
-- n==0 case: 0 rows-affected means EITHER "stale replay" (rows exist
-- with projection_version >= the replaying event's sequence_num) OR
-- "first rotation for this (device, action, path)" (no rows at all).
-- The listener proceeds to insert when no rows exist, and short-
-- circuits when rows exist (= the stale-replay case).
SELECT EXISTS (
    SELECT 1 FROM luks_keys_projection
    WHERE device_id = $1
      AND action_id = $2
      AND device_path = $3
);

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

-- ListLuksRevocationCandidates returns recent luks_key revocation-request /
-- dispatch events for Go-side (device_id, action_id) filtering. Wave E.2
-- moved the filter out of SQL — data->>'device_id' and ->>'action_id'
-- were the last JSONB operators on the events table, blocking the
-- portable-storage goal (tracker #242). The repo method consumes this
-- result and short-circuits on the first match.
--
-- The LIMIT bounds the worst case: the matching event is typically the
-- most recent one for the requested pair. 1000 covers many devices'
-- recent revocation traffic without any practical risk of scanning past
-- the target. If the projection ever holds more pending revocations
-- than that, raise the LIMIT or paginate — but the inbox worker calls
-- this once per agent outcome, so volume stays bounded in practice.
--
-- name: ListLuksRevocationCandidates :many
SELECT stream_id, data
FROM events
WHERE stream_type = 'luks_key'
  AND event_type IN ('LuksDeviceKeyRevocationRequested', 'LuksDeviceKeyRevocationDispatched')
ORDER BY sequence_num DESC
LIMIT 1000;
