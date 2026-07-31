-- The host-authorized bootstrap-admin token.
--
-- One row in `tokens`, distinguished by its reserved name. Only the
-- SHA-256 digest of the bearer value is stored: the token is printed
-- once by the command that mints it and is never recoverable. Owner is
-- NULL because the bootstrap principal is deliberately not a user.

-- name: InsertBootstrapAdminToken :one
INSERT INTO tokens (id, value_hash, name, one_time, max_uses, current_uses, expires_at, created_at, created_by, owner_id, disabled, is_deleted)
VALUES ($1, $2, sqlc.arg(reserved_name), TRUE, 1, 0, $3, $4, sqlc.arg(created_by), NULL, FALSE, FALSE)
RETURNING *;

-- name: ConsumeBootstrapAdminToken :one
-- The consume-once conditional write. Every condition is evaluated by
-- the UPDATE itself, so two concurrent presentations of the same token
-- cannot both observe current_uses < max_uses and both succeed: the
-- second finds no row.
UPDATE tokens
SET current_uses = current_uses + 1
WHERE value_hash = $1
  AND name = sqlc.arg(reserved_name)
  AND is_deleted = FALSE
  AND disabled = FALSE
  AND current_uses < max_uses
  AND (expires_at IS NULL OR expires_at > sqlc.arg(now))
RETURNING *;

-- name: RetireBootstrapAdminTokens :execrows
-- Minting a new bootstrap token retires every outstanding one, so at
-- most one host-authorized token can ever be presentable.
UPDATE tokens SET is_deleted = TRUE
WHERE name = sqlc.arg(reserved_name) AND is_deleted = FALSE;

-- name: CountLiveBootstrapAdminTokens :one
SELECT COUNT(*) FROM tokens
WHERE name = sqlc.arg(reserved_name)
  AND is_deleted = FALSE
  AND disabled = FALSE
  AND current_uses < max_uses
  AND (expires_at IS NULL OR expires_at > sqlc.arg(now));
