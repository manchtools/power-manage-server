-- Per-user DEK envelope (spec 19 / ADR 0030). The wrapped_dek is the
-- KEK-wrapped data-encryption key every PII field of the user's events
-- is sealed under; deleting the row IS the erasure ("crypto-shred").

-- name: InsertUserEncryptionKey :execrows
-- ON CONFLICT DO NOTHING: minting is first-write-wins so a re-provision
-- race (e.g. SCIM retrying a create) can never silently REPLACE a DEK
-- that already sealed PII — replacing it would be an accidental shred.
INSERT INTO user_encryption_keys (user_id, wrapped_dek)
VALUES ($1, $2)
ON CONFLICT (user_id) DO NOTHING;

-- name: GetUserEncryptionKey :one
SELECT * FROM user_encryption_keys WHERE user_id = $1;

-- name: DeleteUserEncryptionKey :execrows
-- THE crypto-shred: destroying the wrapped DEK makes every copy of the
-- user's PII (live log, archives, future rebuilds) permanently
-- unreadable. Called only from the shared delete-with-shred flow.
DELETE FROM user_encryption_keys WHERE user_id = $1;

-- name: CountUserEncryptionKeys :one
SELECT COUNT(*) FROM user_encryption_keys;
