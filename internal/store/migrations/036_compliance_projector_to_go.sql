-- Replace project_compliance_event() with a no-op stub. The actual
-- projection logic now lives in projectors.ComplianceListener (Go,
-- post-commit). The shared project_event() dispatcher trigger still
-- PERFORMs project_compliance_event(NEW) for every compliance-stream
-- event; the no-op stub keeps that dispatch quiet (no
-- plpgsql_projection_errors entries) until the Phase 2 cleanup
-- migration drops every still-PL/pgSQL WHEN clause from the dispatcher.
--
-- Behavioural delta:
--   - Before: PL/pgSQL projector ran inside the AppendEvent
--     transaction. Both event types (ComplianceResultUpdated,
--     ComplianceResultRemoved) and their cascade
--     (evaluate_device_compliance_policies) were atomic with the
--     event commit.
--   - After: Go listener fires post-commit. Both event types wrap
--     their writes (UPSERT/DELETE + reevaluate cascade) in
--     store.WithTx so the cascade stays atomic with itself, but not
--     with the event commit. The handler's read-after-write paths
--     (the inbox worker reading back compliance_results_projection
--     after AppendEvent, plus any handler that lists device
--     compliance state) still see the projection because
--     fireListeners is synchronous — the listener has already run by
--     the time AppendEvent returns.
--
-- Tightening: the UPSERT on compliance_results_projection now carries
-- an explicit `WHERE projection_version < EXCLUDED.projection_version`
-- predicate on its UPDATE branch, rejecting stale reconciler replays.
-- The PL/pgSQL projector stamped projection_version without a guard,
-- so a stale ComplianceResultUpdated re-applied later would silently
-- rewind action_name + compliant + detection_output.
--
-- Asymmetric-guard discipline (per the role + identity_provider +
-- action_set + assignment + user_group + device_group +
-- compliance_policy ports): the UPSERT's UPDATE branch is the only
-- mutation step on the projection — no parent table to Claim against
-- (compliance_results_projection has no header row). The
-- reevaluate_device_compliance_policies cascade is unconditional
-- under the PL/pgSQL projector and stays unconditional here: the
-- shim is idempotent on the device-policy state, so re-running it on
-- a stale-rejected UPSERT is harmless (and matches the legacy
-- behaviour of the PL/pgSQL projector, which also called the
-- reevaluator unconditionally on every event).
--
-- action_name preservation: a duplicate ComplianceResultUpdated that
-- omits action_name (decoder collapses missing → "") MUST NOT erase
-- a previously-set action_name. The PL/pgSQL projector did
-- `COALESCE(payload->>'action_name', existing.action_name)`; the Go
-- port preserves that semantic via NULLIF + COALESCE in the UPSERT
-- (matches the PR #178 CR catch on the compliance_policy rule
-- UPSERT).
--
-- Reevaluation engine scope: per #136 the
-- evaluate_device_compliance_policies(p_device_id) function — and
-- the per-policy evaluator family it dispatches to — STAY in PL/pgSQL
-- until a later phase. The Go listener calls into the existing shim
-- (EvaluateDeviceCompliancePolicies, reused from the assignment
-- port's sqlc generation) so device compliance status reflects every
-- result mutation; the eval engine itself runs unchanged inside
-- Postgres.
--
-- See manchtools/power-manage-server#136. Sixth port under Phase 2
-- of tracker #107's projector-migration pattern.

-- +goose Up

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_compliance_event(event events) RETURNS void AS $$
BEGIN
    -- No-op: ported to projectors.ComplianceListener. See migration
    -- comment + the listener wiring in cmd/control/main.go via
    -- projectors.WireAll.
    NULL;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd


-- +goose Down

-- Restore the PL/pgSQL projector verbatim from migration 003 (the
-- last definition before this port). Mirrors the
-- project_compliance_event() body added in 018_compliance_policies
-- and consolidated into 003_extended_projectors.

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_compliance_event(event events) RETURNS void AS $$
BEGIN
    CASE event.event_type
        WHEN 'ComplianceResultUpdated' THEN
            INSERT INTO compliance_results_projection (
                device_id, action_id, action_name, compliant, detection_output,
                checked_at, projection_version
            ) VALUES (
                event.data->>'device_id',
                event.data->>'action_id',
                COALESCE(event.data->>'action_name', ''),
                COALESCE((event.data->>'compliant')::boolean, false),
                event.data->'detection_output',
                event.occurred_at,
                event.sequence_num
            )
            ON CONFLICT (device_id, action_id) DO UPDATE SET
                action_name = COALESCE(event.data->>'action_name', compliance_results_projection.action_name),
                compliant = COALESCE((event.data->>'compliant')::boolean, false),
                detection_output = event.data->'detection_output',
                checked_at = event.occurred_at,
                projection_version = event.sequence_num;

            -- Evaluate compliance policies (falls back to simple check if no policies assigned)
            PERFORM evaluate_device_compliance_policies(event.data->>'device_id');

        WHEN 'ComplianceResultRemoved' THEN
            DELETE FROM compliance_results_projection
            WHERE device_id = event.data->>'device_id'
              AND action_id = event.data->>'action_id';

            -- Re-evaluate compliance policies
            PERFORM evaluate_device_compliance_policies(event.data->>'device_id');

        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
