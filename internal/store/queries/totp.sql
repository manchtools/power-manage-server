-- name: GetTOTPByUserID :one
SELECT * FROM totp_projection WHERE user_id = $1;

-- name: GetTOTPStatus :one
SELECT enabled,
       (SELECT count(*) FROM unnest(backup_codes_used) AS u WHERE u = FALSE)::int AS backup_codes_remaining
FROM totp_projection WHERE user_id = $1;

-- name: IsTOTPEnabled :one
SELECT totp_enabled FROM users_projection WHERE id = $1 AND is_deleted = FALSE;

-- Write-side queries for the Go totp projector (#97). Replace the
-- per-event branches of the deleted PL/pgSQL project_totp_event
-- function. Each query mirrors one branch's effect; the listener
-- chooses which to call based on the event_type.
--
-- TOTPSetupInitiated upserts the row — re-initiation by the same
-- user before verifying replaces secret + backup codes and resets
-- verified/enabled to FALSE. backup_codes_used is sized to match
-- backup_codes_hash by emitting an array of FALSE of equal length.
--
-- name: UpsertTotpProjection :exec
INSERT INTO totp_projection (
    user_id, secret_encrypted, verified, enabled,
    backup_codes_hash, backup_codes_used,
    created_at, updated_at, projection_version
) VALUES (
    $1, $2, FALSE, FALSE,
    $3,
    array_fill(FALSE::boolean, ARRAY[array_length($3::text[], 1)]),
    $4, $4, $5
)
ON CONFLICT (user_id) DO UPDATE SET
    secret_encrypted = EXCLUDED.secret_encrypted,
    verified = FALSE,
    enabled = FALSE,
    backup_codes_hash = EXCLUDED.backup_codes_hash,
    backup_codes_used = EXCLUDED.backup_codes_used,
    updated_at = EXCLUDED.updated_at,
    projection_version = EXCLUDED.projection_version;

-- name: VerifyTotpProjection :exec
UPDATE totp_projection
SET verified = TRUE,
    enabled = TRUE,
    updated_at = $2,
    projection_version = $3
WHERE user_id = $1;

-- name: DeleteTotpProjection :exec
DELETE FROM totp_projection WHERE user_id = $1;

-- TOTPBackupCodeUsed updates a 1-indexed slot in backup_codes_used.
-- The PL/pgSQL projector used `[(idx)::int + 1]` — we add the +1 in
-- Go before passing the parameter so the SQL stays clean.
--
-- name: MarkTotpBackupCodeUsed :exec
UPDATE totp_projection
SET backup_codes_used[$2::int] = TRUE,
    updated_at = $3,
    projection_version = $4
WHERE user_id = $1;

-- name: RegenerateTotpBackupCodes :exec
UPDATE totp_projection
SET backup_codes_hash = $2,
    backup_codes_used = array_fill(FALSE::boolean, ARRAY[array_length($2::text[], 1)]),
    updated_at = $3,
    projection_version = $4
WHERE user_id = $1;

-- Cross-stream effect: TOTP events also flip
-- users_projection.totp_enabled. Was an inline UPDATE inside the
-- deleted PL/pgSQL projector. Sqlc'd here so the Go listener can
-- call it explicitly.
--
-- name: SetUserTotpEnabled :exec
UPDATE users_projection
SET totp_enabled = $2,
    updated_at = $3,
    projection_version = $4
WHERE id = $1;
