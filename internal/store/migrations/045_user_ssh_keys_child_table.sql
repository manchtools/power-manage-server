-- Wave E.3 (tracker manchtools/power-manage-server#242): normalize the
-- users_projection.ssh_public_keys JSONB array into a relational child
-- table. The previous shape (jsonb_array_elements + array-append +
-- filter-by-id) doesn't translate to non-Postgres backends; INSERT /
-- DELETE against a child table does.
--
-- Idempotency for projector replay: PRIMARY KEY (user_id, key_id)
-- combined with ON CONFLICT DO NOTHING on insert (handled in the new
-- sqlc query) makes UserSshKeyAdded replays a safe no-op. DELETE is
-- inherently idempotent.

-- +goose Up
CREATE TABLE user_ssh_keys (
    user_id    TEXT        NOT NULL REFERENCES users_projection(id) ON DELETE CASCADE,
    key_id     TEXT        NOT NULL,
    public_key TEXT,
    comment    TEXT,
    added_at   TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (user_id, key_id)
);

CREATE INDEX idx_user_ssh_keys_user ON user_ssh_keys(user_id);

INSERT INTO user_ssh_keys (user_id, key_id, public_key, comment, added_at)
SELECT
    u.id,
    e.value->>'id',
    NULLIF(e.value->>'public_key', ''),
    NULLIF(e.value->>'comment', ''),
    COALESCE((e.value->>'added_at')::TIMESTAMPTZ, u.created_at)
FROM users_projection u,
     jsonb_array_elements(u.ssh_public_keys) AS e(value)
WHERE u.ssh_public_keys IS NOT NULL
  AND jsonb_typeof(u.ssh_public_keys) = 'array'
  AND e.value->>'id' IS NOT NULL
ON CONFLICT (user_id, key_id) DO NOTHING;

ALTER TABLE users_projection DROP COLUMN ssh_public_keys;

-- +goose Down
ALTER TABLE users_projection
    ADD COLUMN ssh_public_keys JSONB NOT NULL DEFAULT '[]';

UPDATE users_projection u
SET ssh_public_keys = COALESCE((
        SELECT jsonb_agg(jsonb_build_object(
            'id', k.key_id,
            'public_key', k.public_key,
            'comment', k.comment,
            'added_at', k.added_at
        ))
        FROM user_ssh_keys k
        WHERE k.user_id = u.id
    ), '[]'::JSONB);

DROP INDEX IF EXISTS idx_user_ssh_keys_user;
DROP TABLE user_ssh_keys;
