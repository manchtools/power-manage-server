-- +goose Up
-- Audit N007: luks_keys_projection had no projection_version column,
-- so the LUKS listener could not implement the asymmetric stale-replay
-- guard pattern that the LPS listener gained in #167 (audit F020/F021).
-- A reconciler-driven re-delivery of an old LuksKeyRotated event would
-- re-mark the current row as not-current, then insert a stale duplicate
-- (the trim-to-3 prunes by rotated_at, so the legacy real-current row
-- can survive but its is_current flag stays wrong until the next
-- rotation overwrites it).
--
-- Default 0 backfills existing rows; new rows get the event's
-- sequence_num via the listener. Older rows simply get treated as
-- "no version" — the guard trips on any future replay because
-- 0 < (any new event's sequence_num). The is_current flag for legacy
-- rows is correct as-of-write; future rotations overwrite it through
-- the same guarded path.

ALTER TABLE luks_keys_projection
    ADD COLUMN projection_version BIGINT NOT NULL DEFAULT 0;

-- +goose Down
ALTER TABLE luks_keys_projection DROP COLUMN projection_version;
