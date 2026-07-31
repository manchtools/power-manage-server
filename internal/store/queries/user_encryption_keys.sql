-- Per-subject data-encryption keys. wrapped_dek is the subject's DEK
-- wrapped under the deployment KEK; every value sealed for that
-- subject — including class-three audit detail, which is never
-- deleted — is readable only through it.

-- name: InsertUserEncryptionKey :execrows
-- ON CONFLICT DO NOTHING: minting is first-write-wins, so a
-- re-provision race can never silently REPLACE a key that has already
-- sealed data. Replacing it would be an accidental, irreversible
-- erasure.
INSERT INTO user_encryption_keys (user_id, wrapped_dek)
VALUES ($1, $2)
ON CONFLICT (user_id) DO NOTHING;

-- name: GetUserEncryptionKey :one
SELECT * FROM user_encryption_keys WHERE user_id = $1;

-- name: DeleteUserEncryptionKey :execrows
-- The erasure itself: destroying the wrapped key makes every copy of
-- the subject's sealed data — live rows, archives, backups —
-- permanently unreadable at once. There is no recovery path, which is
-- the point.
DELETE FROM user_encryption_keys WHERE user_id = $1;

-- name: CountUserEncryptionKeys :one
SELECT COUNT(*) FROM user_encryption_keys;
