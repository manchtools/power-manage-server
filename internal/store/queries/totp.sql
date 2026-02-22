-- name: GetTOTPByUserID :one
SELECT * FROM totp_projection WHERE user_id = $1;

-- name: GetTOTPStatus :one
SELECT enabled,
       (SELECT count(*) FROM unnest(backup_codes_used) AS u WHERE u = FALSE)::int AS backup_codes_remaining
FROM totp_projection WHERE user_id = $1;

-- name: IsTOTPEnabled :one
SELECT totp_enabled FROM users_projection WHERE id = $1 AND is_deleted = FALSE;
