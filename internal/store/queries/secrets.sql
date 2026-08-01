-- Current and bounded historical device secrets. Secret values remain
-- AES-GCM ciphertext here and are opened only by the authorized RPC sink.

-- name: ListCurrentLpsPasswords :many
SELECT p.id, p.device_id, d.hostname AS device_hostname,
       p.action_id, COALESCE(a.name, '')::text AS action_name,
       p.username, p.password, p.rotated_at, p.rotation_reason
FROM lps_passwords p
JOIN devices d ON d.id = p.device_id AND d.is_deleted = FALSE
LEFT JOIN actions a ON a.id = p.action_id AND a.is_deleted = FALSE
WHERE p.device_id = $1 AND p.is_current = TRUE
ORDER BY p.action_id, p.username, p.id;

-- name: ListLpsPasswordHistory :many
SELECT id, device_id, device_hostname, action_id, action_name,
       username, password, rotated_at, rotation_reason
FROM (
    SELECT p.id, p.device_id, d.hostname AS device_hostname,
           p.action_id, COALESCE(a.name, '')::text AS action_name,
           p.username, p.password, p.rotated_at, p.rotation_reason,
           row_number() OVER (
               PARTITION BY p.action_id
               ORDER BY p.rotated_at DESC, p.id DESC
           ) AS history_position
    FROM lps_passwords p
    JOIN devices d ON d.id = p.device_id AND d.is_deleted = FALSE
    LEFT JOIN actions a ON a.id = p.action_id AND a.is_deleted = FALSE
    WHERE p.device_id = $1 AND p.is_current = FALSE
) ranked
WHERE history_position <= 3
ORDER BY rotated_at DESC, id DESC;

-- name: ListCurrentLuksKeys :many
SELECT k.id, k.device_id, d.hostname AS device_hostname,
       k.action_id, COALESCE(a.name, '')::text AS action_name,
       k.device_path, k.passphrase, k.rotated_at, k.rotation_reason,
       k.revocation_status, k.revocation_error, k.revocation_at
FROM luks_keys k
JOIN devices d ON d.id = k.device_id AND d.is_deleted = FALSE
LEFT JOIN actions a ON a.id = k.action_id AND a.is_deleted = FALSE
WHERE k.device_id = $1 AND k.is_current = TRUE
ORDER BY k.action_id, k.device_path, k.id;

-- name: ListLuksKeyHistory :many
SELECT id, device_id, device_hostname, action_id, action_name,
       device_path, passphrase, rotated_at, rotation_reason,
       revocation_status, revocation_error, revocation_at
FROM (
    SELECT k.id, k.device_id, d.hostname AS device_hostname,
           k.action_id, COALESCE(a.name, '')::text AS action_name,
           k.device_path, k.passphrase, k.rotated_at, k.rotation_reason,
           k.revocation_status, k.revocation_error, k.revocation_at,
           row_number() OVER (
               PARTITION BY k.action_id
               ORDER BY k.rotated_at DESC, k.id DESC
           ) AS history_position
    FROM luks_keys k
    JOIN devices d ON d.id = k.device_id AND d.is_deleted = FALSE
    LEFT JOIN actions a ON a.id = k.action_id AND a.is_deleted = FALSE
    WHERE k.device_id = $1 AND k.is_current = FALSE
) ranked
WHERE history_position <= 3
ORDER BY rotated_at DESC, id DESC;
