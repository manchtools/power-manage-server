-- +goose Up
-- Audit F020/F021: lps_passwords_projection had no projection_version
-- column, so the LPS listener could not implement the asymmetric
-- stale-replay guard pattern that #101 + #104 + #105 + #106 follow.
-- A reconciler-driven re-delivery of an old LpsPasswordRotated event
-- would re-mark the current row as not-current, then insert a stale
-- duplicate (which the trim-to-3 prunes by rotated_at, but the
-- is_current=FALSE flag stays wrong on the most-recent real password
-- until the next rotation overwrites it).
--
-- Default 0 backfills existing rows; new rows get the event's
-- sequence_num via the listener. Older rows simply get treated as
-- "no version" — the guard trips on any future replay because
-- 0 < (any new event's sequence_num). The is_current flag for
-- legacy rows is correct as-of-write; future rotations overwrite it
-- through the same guarded path.

ALTER TABLE lps_passwords_projection
    ADD COLUMN projection_version BIGINT NOT NULL DEFAULT 0;

-- +goose Down
ALTER TABLE lps_passwords_projection DROP COLUMN projection_version;
