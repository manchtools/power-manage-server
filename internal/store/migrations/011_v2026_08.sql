-- 2026.08 — spec 19 (audit retention), stage C: the sanctioned prune
-- exemption to the append-only event log.
--
-- The append-only trigger (events_block_mutation, 009_v2026_07.sql)
-- rejects ALL DELETE/UPDATE/TRUNCATE on events. Retention needs the
-- ONE sanctioned exception: the prune path deletes events ≤ a
-- checkpoint N after their sealed archive has durably landed.
--
-- Double condition (defense in depth, spec 19 tech design):
--   1. a transaction-scoped guard `pm.prune_active = 'on'` is set by
--      the privileged prune path (SET LOCAL — auto-cleared at
--      COMMIT/ROLLBACK, so it never reaches the next pooled checkout);
--   2. the row being deleted is within the sanctioned checkpoint range
--      `sequence_num <= pm.prune_up_to_seq` — a prune can never delete
--      an event beyond the N it archived, even with the guard set.
-- The paired in-tx EventLogPruned append is enforced by the store's
-- privileged prune method (the third leg of the defense).
--
-- UPDATE and TRUNCATE remain unconditionally rejected — the prune only
-- ever DELETEs, and TRUNCATE would bypass the range bound entirely.

-- +goose Up

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.events_block_mutation() RETURNS trigger
    LANGUAGE plpgsql
AS $$
DECLARE
    prune_active text := current_setting('pm.prune_active', true);
    prune_up_to  text := current_setting('pm.prune_up_to_seq', true);
BEGIN
    -- The ONLY permitted mutation: a DELETE by the sanctioned prune
    -- path, bounded to the archived checkpoint range.
    IF TG_OP = 'DELETE'
       AND prune_active = 'on'
       AND prune_up_to IS NOT NULL
       AND prune_up_to <> ''
       AND OLD.sequence_num <= prune_up_to::bigint THEN
        RETURN OLD;
    END IF;

    RAISE EXCEPTION 'events is append-only: % is not permitted on public.events', TG_OP;
END;
$$;
-- +goose StatementEnd

-- The existing triggers already point at this function; replacing the
-- function body is enough. (events_block_row_mutation on UPDATE/DELETE,
-- events_block_truncate on TRUNCATE.)

-- +goose Down

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.events_block_mutation() RETURNS trigger
    LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'events is append-only: % is not permitted on public.events', TG_OP;
END;
$$;
-- +goose StatementEnd
