-- name: GetLpsKeypair :one
SELECT public_key, private_key_enc, created_at
FROM lps_keypair
WHERE id = 'global';

-- name: InsertLpsKeypair :execrows
-- First-writer-wins under the EnsureLpsKeypair advisory lock. ON CONFLICT
-- DO NOTHING makes a lost race (another replica inserted between our read
-- and write) harmless: :execrows returns 0 and the caller re-reads the
-- winning row rather than clobbering it.
INSERT INTO lps_keypair (id, public_key, private_key_enc)
VALUES ('global', sqlc.arg('public_key'), sqlc.arg('private_key_enc'))
ON CONFLICT (id) DO NOTHING;
