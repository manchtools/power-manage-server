-- Current and bounded historical device-secret metadata. List queries never
-- select ciphertext; one-entry reveal queries are the only administrative
-- read path for stored secret values.

-- name: ListCurrentLpsPasswords :many
SELECT p.id, p.device_id, d.hostname AS device_hostname,
       p.action_id, COALESCE(a.name, '') AS action_name,
       p.username, p.rotated_at, p.rotation_reason
FROM lps_passwords p
JOIN devices d ON d.id = p.device_id AND d.is_deleted = FALSE
LEFT JOIN actions a ON a.id = p.action_id AND a.is_deleted = FALSE
WHERE p.device_id = ? AND p.is_current = TRUE
ORDER BY p.action_id, p.username, p.id;

-- name: ListLpsPasswordHistory :many
SELECT id, device_id, device_hostname, action_id, action_name,
       username, rotated_at, rotation_reason
FROM (
    SELECT p.id, p.device_id, d.hostname AS device_hostname,
           p.action_id, COALESCE(a.name, '') AS action_name,
           p.username, p.rotated_at, p.rotation_reason,
           row_number() OVER (
               PARTITION BY p.action_id
               ORDER BY p.rotated_at DESC, p.id DESC
           ) AS history_position
    FROM lps_passwords p
    JOIN devices d ON d.id = p.device_id AND d.is_deleted = FALSE
    LEFT JOIN actions a ON a.id = p.action_id AND a.is_deleted = FALSE
    WHERE p.device_id = ? AND p.is_current = FALSE
) ranked
WHERE history_position <= 3
ORDER BY rotated_at DESC, id DESC;

-- name: GetLpsPasswordForReveal :one
SELECT id, device_id, action_id, password
FROM lps_passwords
WHERE id = ?;

-- name: InsertLuksToken :one
INSERT INTO luks_tokens (
    id, device_id, action_id, token, min_length, complexity, created_at, expires_at
) VALUES (
    sqlc.arg(id), sqlc.arg(device_id), sqlc.arg(action_id), sqlc.arg(token),
    sqlc.arg(min_length), sqlc.arg(complexity), sqlc.arg(created_at), sqlc.arg(expires_at)
)
RETURNING *;

-- name: ConsumeLuksToken :one
UPDATE luks_tokens
SET used = TRUE
WHERE token = sqlc.arg(token)
  AND device_id = sqlc.arg(device_id)
  AND used = FALSE
  AND expires_at > sqlc.arg(now)
RETURNING *;

-- name: GetCurrentLuksKeyForAgent :one
SELECT * FROM luks_keys
WHERE device_id = sqlc.arg(device_id)
  AND action_id = sqlc.arg(action_id)
  AND is_current = TRUE
ORDER BY rotated_at DESC, id DESC
LIMIT 1;

-- name: RetireCurrentLuksKeys :execrows
UPDATE luks_keys SET is_current = FALSE
WHERE device_id = sqlc.arg(device_id)
  AND action_id = sqlc.arg(action_id)
  AND is_current = TRUE;

-- name: InsertLuksKey :one
INSERT INTO luks_keys (
    id, device_id, action_id, device_path, passphrase,
    rotated_at, rotation_reason, created_at
) VALUES (
    sqlc.arg(id), sqlc.arg(device_id), sqlc.arg(action_id),
    sqlc.arg(device_path), sqlc.arg(passphrase), sqlc.arg(rotated_at),
    sqlc.arg(rotation_reason), sqlc.arg(created_at)
)
RETURNING *;

-- name: RetireCurrentLpsPassword :execrows
UPDATE lps_passwords SET is_current = FALSE
WHERE device_id = sqlc.arg(device_id)
  AND action_id = sqlc.arg(action_id)
  AND username = sqlc.arg(username)
  AND is_current = TRUE;

-- name: InsertLpsPassword :one
INSERT INTO lps_passwords (
    id, device_id, action_id, username, password,
    rotated_at, rotation_reason, created_at
) VALUES (
    sqlc.arg(id), sqlc.arg(device_id), sqlc.arg(action_id),
    sqlc.arg(username), sqlc.arg(password), sqlc.arg(rotated_at),
    sqlc.arg(rotation_reason), sqlc.arg(created_at)
)
RETURNING *;

-- name: ListCurrentLuksKeys :many
SELECT k.id, k.device_id, d.hostname AS device_hostname,
       k.action_id, COALESCE(a.name, '') AS action_name,
       k.device_path, k.rotated_at, k.rotation_reason,
       k.revocation_status, k.revocation_error, k.revocation_at
FROM luks_keys k
JOIN devices d ON d.id = k.device_id AND d.is_deleted = FALSE
LEFT JOIN actions a ON a.id = k.action_id AND a.is_deleted = FALSE
WHERE k.device_id = ? AND k.is_current = TRUE
ORDER BY k.action_id, k.device_path, k.id;

-- name: ListLuksKeyHistory :many
SELECT id, device_id, device_hostname, action_id, action_name,
       device_path, rotated_at, rotation_reason,
       revocation_status, revocation_error, revocation_at
FROM (
    SELECT k.id, k.device_id, d.hostname AS device_hostname,
           k.action_id, COALESCE(a.name, '') AS action_name,
           k.device_path, k.rotated_at, k.rotation_reason,
           k.revocation_status, k.revocation_error, k.revocation_at,
           row_number() OVER (
               PARTITION BY k.action_id
               ORDER BY k.rotated_at DESC, k.id DESC
           ) AS history_position
    FROM luks_keys k
    JOIN devices d ON d.id = k.device_id AND d.is_deleted = FALSE
    LEFT JOIN actions a ON a.id = k.action_id AND a.is_deleted = FALSE
    WHERE k.device_id = ? AND k.is_current = FALSE
) ranked
WHERE history_position <= 3
ORDER BY rotated_at DESC, id DESC;

-- name: GetLuksKeyForReveal :one
SELECT id, device_id, action_id, passphrase
FROM luks_keys
WHERE id = ?;

-- name: GetLuksRevocationTarget :one
SELECT count(*) AS key_count,
       EXISTS (
           SELECT 1 FROM luks_keys pending
           WHERE pending.device_id = sqlc.arg(device_id)
             AND pending.action_id = sqlc.arg(action_id)
             AND pending.is_current = TRUE
             AND pending.revocation_status = 'dispatched'
       ) AS dispatch_pending,
       EXISTS (
           SELECT 1 FROM luks_keys revoked
           WHERE revoked.device_id = sqlc.arg(device_id)
             AND revoked.action_id = sqlc.arg(action_id)
             AND revoked.is_current = TRUE
             AND revoked.revocation_status = 'success'
       ) AS already_revoked
FROM luks_keys
WHERE device_id = sqlc.arg(device_id)
  AND action_id = sqlc.arg(action_id)
  AND is_current = TRUE;

-- name: MarkLuksKeyRevocationDispatched :execrows
UPDATE luks_keys
SET revocation_status = 'dispatched',
    revocation_error = NULL,
    revocation_at = sqlc.arg(revocation_at)
WHERE device_id = sqlc.arg(device_id)
  AND action_id = sqlc.arg(action_id)
  AND is_current = TRUE
  AND COALESCE(revocation_status, '') NOT IN ('dispatched', 'success');

-- name: MarkLuksKeyRevocationDispatchFailed :execrows
UPDATE luks_keys
SET revocation_status = 'failed',
    revocation_error = 'device unavailable',
    revocation_at = sqlc.arg(revocation_at)
WHERE device_id = sqlc.arg(device_id)
  AND action_id = sqlc.arg(action_id)
  AND is_current = TRUE
  AND revocation_status = 'dispatched';

-- name: CompleteLuksKeyRevocation :execrows
UPDATE luks_keys
SET revocation_status = sqlc.arg(revocation_status),
    revocation_error = sqlc.narg(revocation_error),
    revocation_at = sqlc.arg(revocation_at)
WHERE device_id = sqlc.arg(device_id)
  AND action_id = sqlc.arg(action_id)
  AND is_current = TRUE
  AND revocation_status = 'dispatched';
