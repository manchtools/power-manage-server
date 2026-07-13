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
-- columns are already text, the loop selects nothing, and the FK drop/re-add
-- nets to a no-op.
--
-- At v2026.07 the uuid columns were exactly: events.id (PK),
-- lps_passwords_projection.id, luks_keys_projection.id, luks_tokens.id, and
-- security_alerts_projection.event_id (the sole FK, -> events.id). The block is
-- introspective rather than hardcoded so it also repairs any older schema that
-- carried additional uuid columns.

-- +goose Up
-- +goose StatementBegin
DO $$
DECLARE
    r RECORD;
BEGIN
    -- Drop the one FK spanning two uuid columns so both endpoints can be
    -- retyped. IF EXISTS keeps this a no-op if it was already removed.
    IF EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE constraint_schema = 'public'
          AND constraint_name = 'security_alerts_projection_event_id_fkey'
    ) THEN
        ALTER TABLE public.security_alerts_projection
            DROP CONSTRAINT security_alerts_projection_event_id_fkey;
    END IF;

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

    -- Recreate the FK now that both endpoints are text. Only if it is currently
    -- absent (we may have just dropped it, or a fresh DB still has the text
    -- version from 007_foreign_keys.sql — in which case leave it be).
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE constraint_schema = 'public'
          AND constraint_name = 'security_alerts_projection_event_id_fkey'
    ) AND EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'security_alerts_projection'
    ) THEN
        ALTER TABLE public.security_alerts_projection
            ADD CONSTRAINT security_alerts_projection_event_id_fkey
            FOREIGN KEY (event_id) REFERENCES public.events(id);
    END IF;
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
