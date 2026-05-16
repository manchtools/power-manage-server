-- PostgreSQL extensions the schema depends on. Currently just pgcrypto for gen_random_bytes / gen_random_uuid.
--
-- Wave H consolidation (tracker manchtools/power-manage-server#242):
-- replaces the 49 historical migrations with a small thematic set
-- containing the current schema. Existing deployments are broken on
-- purpose — fresh deploys run this set cleanly.
--
-- Generated from a pg_dump --schema-only of a testcontainer that
-- replayed every original migration, then split by domain. Order
-- between files is irrelevant for fresh setup; goose runs them in
-- numeric order.

-- +goose Up

--
-- Name: pgcrypto; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;


-- +goose Down

-- Intentionally not reversible — see header.
SELECT 1;
