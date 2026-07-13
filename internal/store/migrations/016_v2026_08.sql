-- 2026.08 — repair leftover uuid identifier columns on upgraded databases.
--
-- Spec 20 (#513, "ULID identifiers everywhere") changed the identifier
-- columns from `uuid DEFAULT gen_random_uuid()` to `text` by EDITING the
-- already-shipped migration files (002_event_store.sql, 004_devices.sql) in
-- place, rather than adding a forward ALTER migration. goose tracks applied
-- migrations by version number, never by file content, so a database created
-- on v2026.07 (which recorded 001-009 as applied with the uuid columns) never
-- re-runs the edited 002/004 — it keeps the original uuid columns while the
-- code now mints ULID strings. The first `AppendEvent` after upgrade fails with
-- `invalid input syntax for type uuid: "01K..." (22P02)`.
--
-- This forward migration converts every remaining uuid-typed column in the
-- public schema to text. It is idempotent: on a fresh v2026.08 database the
-- columns are already text, the loop selects nothing, and the constraint drop
-- is a no-op.
--
-- At v2026.07 the uuid columns were exactly: events.id (PK),
-- lps_passwords_projection.id, luks_keys_projection.id, luks_tokens.id, and
-- security_alerts_projection.event_id. The loop is introspective rather than
-- hardcoded so it also repairs any older schema that carried additional uuid
-- columns.
--
-- The only FK spanning two of those columns —
-- security_alerts_projection.event_id -> events.id — was DROPPED for good by
-- 012 (spec 19: a derived projection must not pin the prunable event log), so
-- by the time this migration runs there is no FK to work around. We
-- defensively DROP IF EXISTS to converge to 012's intended no-FK state — this
-- also repairs a DB where the FK was manually re-added out of band — and we
-- NEVER re-add it (re-adding would reintroduce the prune-blocking constraint
-- 012 removed).

-- +goose Up
-- +goose StatementBegin
DO $$
DECLARE
    r RECORD;
BEGIN
    -- Converge to 012's no-FK state so the column retype below is unobstructed.
    -- Normally already gone (012 dropped it); IF EXISTS keeps this a no-op.
    ALTER TABLE public.security_alerts_projection
        DROP CONSTRAINT IF EXISTS security_alerts_projection_event_id_fkey;

    -- Convert every uuid-typed column to text. Drop the gen_random_uuid()
    -- default first (a uuid default is invalid on a text column). No-op on a
    -- fresh v2026.08 DB where nothing is uuid-typed.
    FOR r IN
        SELECT table_schema, table_name, column_name
        FROM information_schema.columns
        WHERE table_schema = 'public' AND udt_name = 'uuid'
    LOOP
        EXECUTE format('ALTER TABLE %I.%I ALTER COLUMN %I DROP DEFAULT',
                       r.table_schema, r.table_name, r.column_name);
        EXECUTE format('ALTER TABLE %I.%I ALTER COLUMN %I TYPE text USING %I::text',
                       r.table_schema, r.table_name, r.column_name, r.column_name);
    END LOOP;
END $$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- Irreversible data repair. Once the application writes ULID identifiers, the
-- text columns hold values that are not valid uuids ('01K...'), so converting
-- back to uuid would fail with 22P02 and lose data. Down is intentionally a
-- no-op — the correct rollback is to restore from a pre-upgrade backup.
SELECT 1;
-- +goose StatementEnd
