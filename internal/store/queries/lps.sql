-- name: GetCurrentLpsPasswords :many
SELECT * FROM lps_passwords_projection
WHERE device_id = $1 AND is_current = TRUE
ORDER BY rotated_at DESC;

-- name: GetLpsPasswordHistory :many
SELECT * FROM lps_passwords_projection
WHERE device_id = $1 AND is_current = FALSE
ORDER BY rotated_at DESC
LIMIT 20;

-- name: DeleteLpsPasswordsByAction :exec
DELETE FROM lps_passwords_projection WHERE action_id = $1;

-- name: MarkLpsPasswordsNotCurrent :execrows
-- Step 1 of LpsPasswordRotated projection. Flip every prior row for
-- (device_id, username) so the new password (inserted by step 2) is
-- the only is_current=TRUE row.
--
-- The projection_version guard rejects stale-replay re-deliveries:
-- a re-fired old event whose sequence_num is <= the last applied
-- version for any matching row gets 0 rows-affected, and the
-- listener short-circuits the cascade insert + trim. Without the
-- guard, a reconciler-driven re-delivery of an old
-- LpsPasswordRotated would re-mark the latest (real-current) row as
-- not_current and insert a duplicate stale row underneath it.
-- Audit F020/F021.
UPDATE lps_passwords_projection
SET is_current = FALSE,
    projection_version = sqlc.arg('projection_version')
WHERE device_id = $1
  AND username = $2
  AND projection_version < sqlc.arg('projection_version');

-- name: InsertLpsPassword :exec
-- Step 2 of LpsPasswordRotated projection. Inserts the new row only
-- when the listener confirmed via MarkLpsPasswordsNotCurrent's
-- :execrows that this is NOT a stale replay. The listener
-- short-circuits when n==0, so this insert never runs against a
-- stale event. projection_version on the new row is the same
-- sequence_num that just guarded step 1.
INSERT INTO lps_passwords_projection
    (device_id, action_id, username, password, rotated_at, rotation_reason, projection_version)
VALUES ($1, $2, $3, $4, $5, $6, $7);

-- name: LpsPasswordExistsForDeviceUsername :one
-- Companion to the asymmetric stale-replay guard in
-- MarkLpsPasswordsNotCurrent. Used by the listener to disambiguate
-- the n==0 case: 0 rows-affected means EITHER "stale replay"
-- (rows exist with projection_version >= the replaying event's
-- sequence_num) OR "first rotation for this user" (no rows at all).
-- The listener proceeds to insert when no rows exist, and
-- short-circuits when rows exist (= the stale-replay case).
SELECT EXISTS (
    SELECT 1 FROM lps_passwords_projection
    WHERE device_id = $1
      AND username = $2
);

-- name: TrimLpsPasswordsToLast3 :exec
-- Step 3 of LpsPasswordRotated projection. Keep only the latest 3
-- passwords per (device_id, username) — the operational requirement
-- is "the user has the previous password if the rotation was
-- mid-flight"; deeper history bloats the encrypted-password store.
DELETE FROM lps_passwords_projection AS p
WHERE p.device_id = $1
  AND p.username = $2
  AND p.id NOT IN (
      SELECT id FROM lps_passwords_projection
      WHERE device_id = $1
        AND username = $2
      ORDER BY rotated_at DESC
      LIMIT 3
  );
