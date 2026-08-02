-- +goose Up

-- PostgreSQL narrows typo candidates; Go owns final edit-distance acceptance
-- and ordering so the later SQLite/FTS5 port preserves observable behavior.
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- +goose Down

-- Extensions may be shared with operator-owned objects. Do not drop one on a
-- schema rollback merely because this migration made its creation idempotent.
SELECT 1;
