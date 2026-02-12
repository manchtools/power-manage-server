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
