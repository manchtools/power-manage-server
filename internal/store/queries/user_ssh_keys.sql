-- Authorized SSH public keys per user. Public key material is not a
-- secret, but it is the credential that admits a session on a managed
-- device, so every write is an audited mutation and the audit record
-- carries the key's fingerprint rather than the key.

-- name: InsertUserSshKey :one
INSERT INTO user_ssh_keys (user_id, key_id, public_key, comment, added_at)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: GetUserSshKey :one
SELECT * FROM user_ssh_keys WHERE user_id = $1 AND key_id = $2;

-- name: ListUserSshKeys :many
SELECT * FROM user_ssh_keys WHERE user_id = $1 ORDER BY key_id;

-- name: DeleteUserSshKey :one
DELETE FROM user_ssh_keys WHERE user_id = $1 AND key_id = $2 RETURNING *;
