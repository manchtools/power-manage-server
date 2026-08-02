-- Per-subject data-encryption keys. wrapped_dek is the subject's DEK
-- wrapped under the deployment KEK; every value sealed for that
-- subject, including class-three audit detail which is never
-- deleted, is readable only through it.

-- name: InsertUserEncryptionKey :execrows
-- ON CONFLICT DO NOTHING: minting is first-write-wins, so a
-- re-provision race can never silently REPLACE a key that has already
-- sealed data. Replacing it would be an accidental, irreversible
-- erasure.
INSERT INTO user_encryption_keys (user_id, wrapped_dek)
VALUES (?, ?)
ON CONFLICT (user_id) DO NOTHING;

-- name: GetUserEncryptionKey :one
SELECT * FROM user_encryption_keys WHERE user_id = ?;

-- name: DeleteUserEncryptionKey :execrows
-- Deletes the live wrapped key, immediately making sealed subject data in the
-- live database unreadable. A retained SQLite snapshot may still contain an
-- older wrapped-key copy; operators must expire or rewrite those snapshots
-- under the deployment's documented backup-retention policy before claiming
-- permanent erasure across every copy.
DELETE FROM user_encryption_keys WHERE user_id = ?;

-- name: CountUserEncryptionKeys :one
SELECT COUNT(*) FROM user_encryption_keys;
