-- Durable delivery and database-backed jobs.
--
-- Both are ordinary database state. An in-process signal wakes the
-- dispatcher and the scheduler; a periodic database sweep over these
-- tables is the correctness mechanism when a signal is missed or the
-- device is offline.

-- +goose Up

-- ---------------------------------------------------------------------------
-- Deliveries
-- ---------------------------------------------------------------------------

-- One row per manifest handed to one device.
--
-- delivery_id is minted once and stays stable across every transport
-- retry. The agent keeps a durable receipt table keyed by delivery_id,
-- so a replay or a reconnect retry is recognised and the manifest
-- executes exactly once.
--
-- `manifest` holds the complete flat, ordered occurrence list plus the
-- bounded provenance path the agent receives. It is committed before
-- the first send is attempted, which is what makes offline dispatch
-- and sweep recovery possible: the work is durable before anyone tries
-- to move it. Occurrence identity lives inside the payload — duplicate
-- authored occurrences are preserved and executed, and occurrence
-- identity is not delivery identity, so an occurrence must never be
-- promoted to a delivery column.
CREATE TABLE public.deliveries (
    delivery_id      text PRIMARY KEY,
    device_id        text NOT NULL REFERENCES public.devices(id) ON DELETE CASCADE,
    manifest_id      text NOT NULL,
    manifest         jsonb NOT NULL,

    state            text NOT NULL,

    -- The audit operation that initiated this dispatch. Fan-out keeps
    -- the same operation_id, so a result that arrives much later is
    -- still attributable to the request that caused it. Deliberately
    -- not a foreign key: live state must never hold an evidence row
    -- alive, and audit retention must never be blocked by a delivery.
    operation_id     text,

    -- Agent connection epoch that last pushed the row. Epochs increase
    -- monotonically per connection, so a stale connection cannot
    -- deliver new work.
    push_epoch       bigint DEFAULT 0 NOT NULL,
    -- Diagnostic only. Never an input to delivery identity, ordering
    -- or de-duplication.
    attempt_count    integer DEFAULT 0 NOT NULL,

    created_at       timestamp with time zone DEFAULT now() NOT NULL,
    -- Earliest time the sweep may consider this row again.
    available_at     timestamp with time zone DEFAULT now() NOT NULL,
    -- Optional manifest expiry. Product policy; replay protection does
    -- not depend on it.
    expires_at       timestamp with time zone,
    pushed_at        timestamp with time zone,
    acked_receipt_at timestamp with time zone,
    terminal_at      timestamp with time zone,

    result_code      text DEFAULT ''::text NOT NULL,

    CONSTRAINT deliveries_id_ulid
        CHECK (delivery_id ~ '^[0-9A-HJKMNP-TV-Z]{26}$'),
    CONSTRAINT deliveries_device_ulid
        CHECK (device_id ~ '^[0-9A-HJKMNP-TV-Z]{26}$'),
    CONSTRAINT deliveries_manifest_ulid
        CHECK (manifest_id ~ '^[0-9A-HJKMNP-TV-Z]{26}$'),
    CONSTRAINT deliveries_operation_ulid
        CHECK (operation_id IS NULL OR operation_id ~ '^[0-9A-HJKMNP-TV-Z]{26}$'),
    CONSTRAINT deliveries_state_valid
        CHECK (state = ANY (ARRAY[
            'PENDING'::text,
            'PUSHED'::text,
            'ACKED_RECEIPT'::text,
            'SUCCEEDED'::text,
            'PARTIAL'::text,
            'FAILED'::text,
            'EXPIRED'::text,
            'CANCELLED'::text])),
    CONSTRAINT deliveries_attempt_count_nonneg CHECK (attempt_count >= 0),
    CONSTRAINT deliveries_push_epoch_nonneg CHECK (push_epoch >= 0),
    -- The durable state machine, enforced by the database rather than
    -- by every writer remembering the convention:
    --   PENDING       committed, nothing sent yet
    --   PUSHED        written to a connection, receipt not confirmed
    --   ACKED_RECEIPT the agent confirmed DURABLE receipt
    --   terminal      a per-action and manifest result exists, or the
    --                 delivery expired or was cancelled
    CONSTRAINT deliveries_state_timestamps CHECK (
        CASE state
            WHEN 'PENDING' THEN
                pushed_at IS NULL AND acked_receipt_at IS NULL AND terminal_at IS NULL
            WHEN 'PUSHED' THEN
                pushed_at IS NOT NULL AND acked_receipt_at IS NULL AND terminal_at IS NULL
            WHEN 'ACKED_RECEIPT' THEN
                pushed_at IS NOT NULL AND acked_receipt_at IS NOT NULL AND terminal_at IS NULL
            ELSE
                terminal_at IS NOT NULL
        END
    ),
    -- Acknowledgement follows durable receipt, never a successful
    -- socket write, so a result state is only reachable from a
    -- confirmed receipt. EXPIRED and CANCELLED may terminate a
    -- delivery that was never received.
    CONSTRAINT deliveries_results_follow_receipt CHECK (
        state <> ALL (ARRAY['SUCCEEDED'::text, 'PARTIAL'::text, 'FAILED'::text])
        OR acked_receipt_at IS NOT NULL
    ),
    CONSTRAINT deliveries_result_code_token
        CHECK (result_code ~ '^[A-Za-z0-9_.-]{0,64}$')
);

-- The sweep's work list: non-terminal rows, ordered by when they
-- become due.
CREATE INDEX deliveries_sweep_idx
    ON public.deliveries USING btree (available_at)
    WHERE (state = ANY (ARRAY['PENDING'::text, 'PUSHED'::text]));

-- What one agent still owes, oldest first, for the wakeup path.
CREATE INDEX deliveries_device_pending_idx
    ON public.deliveries USING btree (device_id, created_at)
    WHERE (state = ANY (ARRAY['PENDING'::text, 'PUSHED'::text]));

CREATE INDEX deliveries_device_idx ON public.deliveries USING btree (device_id, created_at DESC);
CREATE INDEX deliveries_manifest_idx ON public.deliveries USING btree (manifest_id);
CREATE INDEX deliveries_operation_idx ON public.deliveries USING btree (operation_id);
CREATE INDEX deliveries_expiry_idx
    ON public.deliveries USING btree (expires_at)
    WHERE (expires_at IS NOT NULL AND terminal_at IS NULL);

-- ---------------------------------------------------------------------------
-- Jobs
-- ---------------------------------------------------------------------------

-- Scheduled work. A bounded in-process scheduler claims due rows with
-- a conditional transition:
--
--   UPDATE jobs SET state = 'CLAIMED', claimed_at = now(),
--                   claimed_until = now() + lease, claimed_by = $worker,
--                   attempt_count = attempt_count + 1
--    WHERE job_id = $1
--      AND (   (state = 'PENDING' AND due_at <= now())
--           OR (state = 'CLAIMED' AND claimed_until <= now()))
--
-- Two workers can never both hold a row: the second UPDATE matches
-- zero rows. A worker that dies holding a claim loses it when
-- claimed_until passes, and the row is reclaimed.
CREATE TABLE public.jobs (
    job_id        text PRIMARY KEY,
    kind          text NOT NULL,
    payload       jsonb DEFAULT '{}'::jsonb NOT NULL,

    state         text NOT NULL,
    due_at        timestamp with time zone NOT NULL,

    claimed_at    timestamp with time zone,
    claimed_until timestamp with time zone,
    claimed_by    text DEFAULT ''::text NOT NULL,

    attempt_count integer DEFAULT 0 NOT NULL,
    max_attempts  integer DEFAULT 5 NOT NULL,
    result_code   text DEFAULT ''::text NOT NULL,

    -- Optional idempotency key: at most one live row per key, so a
    -- scheduled singleton cannot be enqueued twice.
    dedupe_key    text,

    created_at    timestamp with time zone DEFAULT now() NOT NULL,
    updated_at    timestamp with time zone DEFAULT now() NOT NULL,
    terminal_at   timestamp with time zone,

    CONSTRAINT jobs_id_ulid CHECK (job_id ~ '^[0-9A-HJKMNP-TV-Z]{26}$'),
    CONSTRAINT jobs_kind_token CHECK (kind ~ '^[a-z][a-z0-9_.]{0,63}$'),
    CONSTRAINT jobs_state_valid
        CHECK (state = ANY (ARRAY[
            'PENDING'::text,
            'CLAIMED'::text,
            'SUCCEEDED'::text,
            'FAILED'::text,
            'CANCELLED'::text])),
    CONSTRAINT jobs_attempt_count_nonneg CHECK (attempt_count >= 0),
    CONSTRAINT jobs_max_attempts_positive CHECK (max_attempts > 0),
    CONSTRAINT jobs_result_code_token CHECK (result_code ~ '^[A-Za-z0-9_.-]{0,64}$'),
    CONSTRAINT jobs_claim_paired
        CHECK ((claimed_at IS NULL) = (claimed_until IS NULL)),
    CONSTRAINT jobs_state_timestamps CHECK (
        CASE state
            WHEN 'PENDING'  THEN terminal_at IS NULL
            WHEN 'CLAIMED'  THEN claimed_at IS NOT NULL AND terminal_at IS NULL
            ELSE terminal_at IS NOT NULL
        END
    )
);

CREATE INDEX jobs_due_idx
    ON public.jobs USING btree (due_at)
    WHERE (state = 'PENDING'::text);

-- Expired leases the sweep reclaims.
CREATE INDEX jobs_lease_idx
    ON public.jobs USING btree (claimed_until)
    WHERE (state = 'CLAIMED'::text);

CREATE INDEX jobs_kind_idx ON public.jobs USING btree (kind, due_at);

CREATE UNIQUE INDEX jobs_dedupe_live_key
    ON public.jobs USING btree (dedupe_key)
    WHERE (dedupe_key IS NOT NULL AND state = ANY (ARRAY['PENDING'::text, 'CLAIMED'::text]));

-- +goose Down

SELECT 1;
