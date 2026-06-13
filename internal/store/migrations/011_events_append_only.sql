-- 011_events_append_only.sql
--
-- Defense-in-depth: enforce the event store's append-only invariant at the
-- DATABASE level, not only in application code. The events table is the
-- system's audit trail and the single source of truth every projection
-- rebuilds from; a compromised gateway, a buggy query, or an operator with
-- direct DB access must not be able to rewrite or erase history. A BEFORE
-- trigger RAISEs on any UPDATE / DELETE / TRUNCATE, so only INSERT (append)
-- and SELECT (read) succeed.
--
-- RebuildAll only TRUNCATEs *_projection tables, never public.events, so this
-- guard does not interfere with projection rebuilds. The application-layer
-- invariant (no sqlc query mutates events) is pinned separately by
-- TestNoSQLCQueryMutatesEvents; this trigger is the belt to that suspenders.

-- +goose Up
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.events_block_mutation() RETURNS trigger
    LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'events is append-only: % is not permitted on public.events', TG_OP;
END;
$$;
-- +goose StatementEnd

-- Row-level guard for UPDATE/DELETE.
CREATE TRIGGER events_block_row_mutation
    BEFORE UPDATE OR DELETE ON public.events
    FOR EACH ROW EXECUTE FUNCTION public.events_block_mutation();

-- Statement-level guard for TRUNCATE (TRUNCATE fires no per-row triggers).
CREATE TRIGGER events_block_truncate
    BEFORE TRUNCATE ON public.events
    FOR EACH STATEMENT EXECUTE FUNCTION public.events_block_mutation();

-- +goose Down
DROP TRIGGER IF EXISTS events_block_truncate ON public.events;
DROP TRIGGER IF EXISTS events_block_row_mutation ON public.events;
DROP FUNCTION IF EXISTS public.events_block_mutation();
