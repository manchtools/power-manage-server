-- 2026.08 — spec 19 (audit retention), Phase-C audit fix F1: enforce the
-- FULL double condition on the prune exemption at the trigger layer.
--
-- The spec (19-audit-retention-and-erasure, tech design) sanctions a
-- DELETE on events only when BOTH hold in the same transaction:
--   1. the SET LOCAL guard (pm.prune_active + pm.prune_up_to_seq) is set
--      by the privileged prune path, AND
--   2. an EventLogPruned marker was appended IN THE SAME TRANSACTION.
--
-- Migration 011 implemented only condition 1 (+ the range bound) and left
-- condition 2 to the Go method — which means any session holding DB
-- credentials could SET LOCAL both guards and silently delete history
-- with NO tamper-evident marker. This migration closes that hole: the
-- trigger itself verifies a marker row whose xmin is the current
-- transaction and whose up_to_seq matches the sanctioned range guard.
-- (The marker is appended BEFORE the delete by the prune method, so it is
-- visible to the trigger's query within the same transaction.)
--
-- Additionally, EventLogPruned rows themselves are now hard-undeletable
-- (AC 24 pinned at the DB layer): the prune chain must stay visible in
-- the live log forever, even inside an otherwise-sanctioned transaction.
--
-- The per-row EXISTS is cheap: idx_events_type (002) narrows it to the
-- handful of EventLogPruned rows.
--
-- Version floor: pg_current_xact_id() and the xid8→xid cast require
-- PostgreSQL 13+ (the project pins 17 in tests, 18 in deploy). The
-- xmin comparison is same-transaction-safe: the prune method appends the
-- marker in this very transaction with no savepoints, so the marker row's
-- xmin IS the top-level xid pg_current_xact_id() returns; 32-bit
-- truncation of the current xid always matches its own xmin.

-- +goose Up

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.events_block_mutation() RETURNS trigger
    LANGUAGE plpgsql
AS $$
DECLARE
    prune_active text := current_setting('pm.prune_active', true);
    prune_up_to  text := current_setting('pm.prune_up_to_seq', true);
BEGIN
    -- The ONLY permitted mutation: a DELETE by the sanctioned prune path,
    -- bounded to the archived checkpoint range, never of a marker row,
    -- and only alongside an EventLogPruned marker appended in THIS
    -- transaction for THIS range (the spec's double condition).
    IF TG_OP = 'DELETE'
       AND prune_active = 'on'
       AND prune_up_to IS NOT NULL
       AND prune_up_to <> ''
       AND OLD.sequence_num <= prune_up_to::bigint
       AND OLD.event_type <> 'EventLogPruned'
       AND EXISTS (
           SELECT 1
             FROM public.events m
            WHERE m.event_type = 'EventLogPruned'
              AND m.xmin = pg_current_xact_id()::xid
              AND (m.data->>'up_to_seq')::bigint = prune_up_to::bigint
       ) THEN
        RETURN OLD;
    END IF;

    RAISE EXCEPTION 'events is append-only: % is not permitted on public.events', TG_OP;
END;
$$;
-- +goose StatementEnd

-- The existing triggers already point at this function; replacing the
-- function body is enough.

-- +goose Down

-- Restore the 011 body (guard + range only, marker enforced in Go).
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.events_block_mutation() RETURNS trigger
    LANGUAGE plpgsql
AS $$
DECLARE
    prune_active text := current_setting('pm.prune_active', true);
    prune_up_to  text := current_setting('pm.prune_up_to_seq', true);
BEGIN
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
