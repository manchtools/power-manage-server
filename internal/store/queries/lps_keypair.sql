-- name: GetLpsKeypair :one
SELECT public_key, private_key_enc, created_at
FROM lps_keypair
WHERE id = 'global';

-- name: UpsertLpsKeypair :exec
-- Projector write for LpsKeypairGenerated (#495): the lps_keypair table is a
-- projection of the singleton lps_keypair/global stream. Idempotent overwrite
-- so a rebuild replay and a live listener re-delivery both converge on the
-- event's values. First-writer-wins now lives at the EVENT layer — the
-- UNIQUE(stream_type, stream_id, stream_version) constraint rejects the
-- losing replica's version-1 append (see api.EnsureLpsKeypair).
INSERT INTO lps_keypair (id, public_key, private_key_enc, created_at)
VALUES ('global', sqlc.arg('public_key'), sqlc.arg('private_key_enc'), sqlc.arg('created_at'))
ON CONFLICT (id) DO UPDATE
SET public_key      = EXCLUDED.public_key,
    private_key_enc = EXCLUDED.private_key_enc,
    created_at      = EXCLUDED.created_at;
