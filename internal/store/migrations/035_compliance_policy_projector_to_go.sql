-- Replace project_compliance_policy_event() with a no-op stub. The
-- actual projection logic now lives in projectors.CompliancePolicyListener
-- (Go, post-commit). The shared project_event() dispatcher trigger
-- still PERFORMs project_compliance_policy_event(NEW) for every
-- compliance_policy-stream event; the no-op stub keeps that dispatch
-- quiet (no plpgsql_projection_errors entries) until the Phase 2
-- cleanup migration drops every still-PL/pgSQL WHEN clause from the
-- dispatcher.
--
-- Behavioural delta:
--   - Before: PL/pgSQL projector ran inside the AppendEvent
--     transaction. The seven event types (Created, Renamed,
--     DescriptionUpdated, Deleted, RuleAdded, RuleRemoved,
--     RuleUpdated) and their cascades (rule wipe / evaluation wipe /
--     reevaluate-devices) were atomic with the event commit.
--   - After: Go listener fires post-commit. Every multi-write event
--     (Deleted, RuleAdded, RuleRemoved, RuleUpdated) wraps its writes
--     in store.WithTx so the cascade stays atomic with itself, but
--     not with the event commit. The handler's read-after-write
--     paths (CreateCompliancePolicy / AddCompliancePolicyRule /
--     DeleteCompliancePolicy etc. reading back from
--     compliance_policies_projection) still see the projection
--     because fireListeners is synchronous — the listener has
--     already run by the time AppendEvent returns.
--
-- Tightening: every UPDATE on compliance_policies_projection
-- (Renamed, DescriptionUpdated, soft-delete, Claim guard) now carries
-- an explicit `WHERE projection_version < $N` guard, rejecting stale
-- reconciler replays. The PL/pgSQL projector stamped
-- projection_version without a guard.
--
-- Asymmetric-guard discipline (per the role + identity_provider +
-- action_set + assignment + user_group + device_group ports):
--   - Deleted: the guarded SoftDelete uses :execrows, and the
--     listener short-circuits the cascade (rule wipe + evaluation
--     wipe + reevaluate-devices) when n == 0 — otherwise a stale
--     CompliancePolicyDeleted re-applied later would silently nuke a
--     freshly-restored policy's rules and trigger a needless device
--     re-evaluation pass.
--   - RuleAdded / RuleRemoved / RuleUpdated: the Claim-first guard
--     (ClaimCompliancePolicyForRuleMutation, :execrows) bumps the
--     parent's projection_version BEFORE any rule-table mutation, and
--     the listener short-circuits when n == 0. This is the lesson
--     from PR #174's CR review: the prior insert-then-recount shape
--     let stale replays silently resurrect removed rules or rewind a
--     fresher RuleUpdated, because the version check was downstream
--     of the child-row mutation.
--
-- Reevaluation engine scope: per #136 the
-- reevaluate_compliance_policy_devices(p_policy_id) function — and
-- the evaluate_device_compliance_policies family it calls — STAY in
-- PL/pgSQL until a later phase. The Go listener calls into the shim
-- (sqlc-generated ReevaluateCompliancePolicyDevices) so device
-- compliance status reflects rule mutations; the eval engine itself
-- runs unchanged inside Postgres.
--
-- See manchtools/power-manage-server#136. Fifth port under Phase 2
-- of tracker #107's projector-migration pattern.

-- +goose Up

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_compliance_policy_event(event events) RETURNS void AS $$
BEGIN
    -- No-op: ported to projectors.CompliancePolicyListener. See
    -- migration comment + the listener wiring in cmd/control/main.go
    -- via projectors.WireAll.
    NULL;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd


-- +goose Down

-- Restore the PL/pgSQL projector verbatim from migration 003 (the
-- last definition before this port). Mirrors the
-- project_compliance_policy_event() body added in 028_fix_compliance_evaluation
-- and consolidated into 003_extended_projectors.

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_compliance_policy_event(event events) RETURNS void AS $$
BEGIN
    CASE event.event_type
        WHEN 'CompliancePolicyCreated' THEN
            INSERT INTO compliance_policies_projection (
                id, name, description, rule_count, created_at,
                created_by, projection_version
            ) VALUES (
                event.stream_id,
                event.data->>'name',
                COALESCE(event.data->>'description', ''),
                0,
                event.occurred_at,
                event.actor_id,
                event.sequence_num
            );

        WHEN 'CompliancePolicyRenamed' THEN
            UPDATE compliance_policies_projection
            SET name = event.data->>'name',
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'CompliancePolicyDescriptionUpdated' THEN
            UPDATE compliance_policies_projection
            SET description = COALESCE(event.data->>'description', ''),
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'CompliancePolicyDeleted' THEN
            UPDATE compliance_policies_projection
            SET is_deleted = TRUE,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

            DELETE FROM compliance_policy_rules_projection WHERE policy_id = event.stream_id;
            DELETE FROM compliance_policy_evaluation_projection WHERE policy_id = event.stream_id;

            -- Re-evaluate affected devices to update their overall status
            PERFORM reevaluate_compliance_policy_devices(event.stream_id);

        WHEN 'CompliancePolicyRuleAdded' THEN
            INSERT INTO compliance_policy_rules_projection (
                policy_id, action_id, action_name, grace_period_hours,
                added_at, projection_version
            ) VALUES (
                event.stream_id,
                event.data->>'action_id',
                COALESCE(event.data->>'action_name', ''),
                COALESCE((event.data->>'grace_period_hours')::INTEGER, 0),
                event.occurred_at,
                event.sequence_num
            ) ON CONFLICT (policy_id, action_id) DO UPDATE SET
                action_name = COALESCE(event.data->>'action_name',
                    compliance_policy_rules_projection.action_name),
                grace_period_hours = COALESCE(
                    (event.data->>'grace_period_hours')::INTEGER, 0),
                projection_version = event.sequence_num;

            UPDATE compliance_policies_projection
            SET rule_count = (
                SELECT COUNT(*) FROM compliance_policy_rules_projection
                WHERE policy_id = event.stream_id
            ), projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'CompliancePolicyRuleRemoved' THEN
            DELETE FROM compliance_policy_rules_projection
            WHERE policy_id = event.stream_id
              AND action_id = event.data->>'action_id';

            UPDATE compliance_policies_projection
            SET rule_count = (
                SELECT COUNT(*) FROM compliance_policy_rules_projection
                WHERE policy_id = event.stream_id
            ), projection_version = event.sequence_num
            WHERE id = event.stream_id;

            DELETE FROM compliance_policy_evaluation_projection
            WHERE policy_id = event.stream_id
              AND action_id = event.data->>'action_id';

            -- Re-evaluate affected devices to update their overall status
            PERFORM reevaluate_compliance_policy_devices(event.stream_id);

        WHEN 'CompliancePolicyRuleUpdated' THEN
            UPDATE compliance_policy_rules_projection
            SET grace_period_hours = COALESCE(
                    (event.data->>'grace_period_hours')::INTEGER, 0),
                projection_version = event.sequence_num
            WHERE policy_id = event.stream_id
              AND action_id = event.data->>'action_id';

        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
