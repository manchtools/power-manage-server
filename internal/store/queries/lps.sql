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

-- name: MarkLpsPasswordsNotCurrent :exec
-- Step 1 of LpsPasswordRotated projection. Flip every prior row for
-- (device_id, username) so the new password (inserted by step 2) is
-- the only is_current=TRUE row. Idempotent: replaying the same event
-- after the new row already landed leaves the projection unchanged
-- because the new row matches WHERE and gets flipped to FALSE — but
-- the listener wraps both writes in a tx, so a replay of the full
-- listener body keeps the (mark-old-false, insert-new-true) pair
-- consistent.
UPDATE lps_passwords_projection
SET is_current = FALSE
WHERE device_id = $1
  AND username = $2;

-- name: InsertLpsPassword :exec
-- Step 2 of LpsPasswordRotated projection. Always inserts a new row
-- — the PL/pgSQL projector did the same, and step 3's trim keeps
-- only the latest 3 by rotated_at so duplicates from a replay are
-- pruned automatically.
INSERT INTO lps_passwords_projection
    (device_id, action_id, username, password, rotated_at, rotation_reason)
VALUES ($1, $2, $3, $4, $5, $6);

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
