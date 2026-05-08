-- Replace project_action_event() AND project_definition_event() with
-- no-op stubs. The actual projection logic now lives in
-- projectors.ActionListener (Go, post-commit). One Go listener owns
-- BOTH stream types because DefinitionCreated dispatches across two
-- projections — synthesise an actions_projection row (when payload
-- carries `action_type`) OR insert a definitions_projection row
-- (otherwise) — and splitting would race the two branches against
-- each other.
--
-- The shared project_event() dispatcher trigger still PERFORMs
-- project_action_event(NEW) for every action-stream event AND
-- project_definition_event(NEW) for every definition-stream event;
-- the no-op stubs keep those dispatches quiet (no
-- plpgsql_projection_errors entries) until the Phase 2 cleanup
-- migration drops every still-PL/pgSQL WHEN clause from the
-- dispatcher.
--
-- Behavioural delta:
--   - Before: PL/pgSQL projector pair ran inside the AppendEvent
--     transaction. Every event type — 5 ActionXxx + 8 DefinitionXxx
--     — and their cascades (action_set member decrement, compliance
--     cascade through 4 tables, per-affected-device reevaluate loop,
--     cross-stream rename of compliance_policy_rules.action_name)
--     were atomic with the event commit.
--   - After: Go listener fires post-commit. Every multi-write event
--     (ActionDeleted, DefinitionMemberAdded/Removed/Reordered) wraps
--     its writes in store.WithTx so the cascade stays atomic with
--     itself, but not with the event commit. The handler's read-
--     after-write paths (CreateAction / RenameAction / DeleteAction
--     etc. reading back from actions_projection) still see the
--     projection because fireListeners is synchronous — the listener
--     has already run by the time AppendEvent returns.
--
-- Tightening: every UPDATE on actions_projection AND
-- definitions_projection now carries an explicit
-- `WHERE projection_version < $N` guard, rejecting stale reconciler
-- replays. The PL/pgSQL projector pair stamped projection_version
-- without a guard, so a stale ActionParamsUpdated re-applied later
-- would silently rewind params + timeout + desired_state + schedule.
--
-- Asymmetric-guard discipline (per the role + identity_provider +
-- action_set + assignment + user_group + device_group +
-- compliance_policy + compliance ports):
--   - ActionDeleted: the guarded SoftDelete uses :execrows. When n==0
--     EVERY downstream cascade is skipped — action_set member
--     decrement, compliance_policy_rules delete + per-policy
--     rule_count decrement, compliance_policy_evaluation delete,
--     compliance_results delete, AND the per-affected-device
--     reevaluate loop. Otherwise an old delete re-applied by the
--     reconciler against a freshly-restored action would silently
--     nuke its compliance footprint and trigger a needless device
--     re-evaluation pass.
--   - ActionRenamed: the guarded Rename UPDATE is :execrows. When
--     n==0 the cross-stream cascade into
--     compliance_policy_rules.action_name is skipped — otherwise a
--     stale rename re-applied after a fresher rename would push the
--     old name into the compliance projection rows.
--   - DefinitionMemberAdded / DefinitionMemberRemoved /
--     DefinitionMemberReordered: the Claim-first guard
--     (ClaimDefinitionForMembership, :execrows) bumps the parent's
--     projection_version BEFORE any membership-table mutation, and the
--     listener short-circuits when n == 0. This is the lesson from
--     PR #174's CR review: the prior insert-then-recount shape let
--     stale replays silently resurrect removed members or rewind a
--     fresher Reorder, because the version check was downstream of
--     the child-row mutation.
--
-- Compliance reevaluation engine scope: per #136 the
-- evaluate_device_compliance_policies(p_device_id) function — and the
-- per-policy evaluator family it dispatches to — STAY in PL/pgSQL
-- until a later phase. The Go listener calls into the existing shim
-- (EvaluateDeviceCompliancePolicies, reused from the assignment
-- port's sqlc generation) so device compliance status reflects every
-- action deletion; the eval engine itself runs unchanged inside
-- Postgres.
--
-- Tracker #136 explicitly required these two functions to be ported
-- TOGETHER in one PR because the DefinitionCreated branch
-- synthesises actions_projection rows (cross-stream effect); a split
-- port would let the action-stream invocation observe a partially-
-- ported state where the definition-stream sibling still wrote to
-- definitions_projection.
--
-- See manchtools/power-manage-server#136. Seventh port under Phase 2
-- of tracker #107's projector-migration pattern.

-- +goose Up

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_action_event(event events) RETURNS void AS $$
BEGIN
    -- No-op: ported to projectors.ActionListener (the listener owns
    -- BOTH stream types). See migration comment + the listener wiring
    -- in cmd/control/main.go via projectors.WireAll.
    NULL;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_definition_event(event events) RETURNS void AS $$
BEGIN
    -- No-op: ported to projectors.ActionListener. See migration
    -- comment + the listener wiring in cmd/control/main.go via
    -- projectors.WireAll.
    NULL;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd


-- +goose Down

-- Restore the PL/pgSQL projector for actions verbatim from migration
-- 002_core_projectors (the last definition before this port). Handles
-- 5 ActionXxx events plus 4 DefinitionXxx events for the synthesised-
-- action path.

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_action_event(event events) RETURNS void AS $$
DECLARE
    v_device_id TEXT;
    v_affected_policies TEXT[];
BEGIN
    CASE event.event_type
        WHEN 'ActionCreated' THEN
            INSERT INTO actions_projection (
                id, name, description, action_type, desired_state,
                params, timeout_seconds, created_at, updated_at, created_by, projection_version,
                is_system, schedule
            ) VALUES (
                event.stream_id,
                event.data->>'name',
                event.data->>'description',
                COALESCE((event.data->>'action_type')::INTEGER, 0),
                COALESCE((event.data->>'desired_state')::INTEGER, 0),
                COALESCE(event.data->'params', '{}'),
                COALESCE((event.data->>'timeout_seconds')::INTEGER, 300),
                event.occurred_at,
                event.occurred_at,
                event.actor_id,
                event.sequence_num,
                COALESCE((event.data->>'is_system')::BOOLEAN, FALSE),
                event.data->'schedule'
            );

        WHEN 'ActionRenamed' THEN
            UPDATE actions_projection
            SET name = event.data->>'name',
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

            -- Cascade rename to compliance policy rules that reference this action.
            UPDATE compliance_policy_rules_projection
            SET action_name = event.data->>'name'
            WHERE action_id = event.stream_id;

        WHEN 'ActionDescriptionUpdated' THEN
            UPDATE actions_projection
            SET description = event.data->>'description',
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'ActionParamsUpdated' THEN
            UPDATE actions_projection
            SET params = COALESCE(event.data->'params', params),
                timeout_seconds = COALESCE((event.data->>'timeout_seconds')::INTEGER, timeout_seconds),
                desired_state = COALESCE((event.data->>'desired_state')::INTEGER, desired_state),
                schedule = COALESCE(event.data->'schedule', schedule),
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'ActionDeleted' THEN
            UPDATE actions_projection
            SET is_deleted = TRUE,
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

            UPDATE action_sets_projection
            SET member_count = member_count - 1
            WHERE id IN (
                SELECT set_id FROM action_set_members_projection WHERE action_id = event.stream_id
            );

            DELETE FROM action_set_members_projection WHERE action_id = event.stream_id;

            -- Clean up compliance data for this action.
            -- Collect affected policy IDs before deleting rules.
            SELECT ARRAY_AGG(DISTINCT policy_id)
            INTO v_affected_policies
            FROM compliance_policy_rules_projection
            WHERE action_id = event.stream_id;

            IF v_affected_policies IS NOT NULL THEN
                UPDATE compliance_policies_projection
                SET rule_count = rule_count - 1
                WHERE id = ANY(v_affected_policies);

                DELETE FROM compliance_policy_rules_projection WHERE action_id = event.stream_id;
                DELETE FROM compliance_policy_evaluation_projection WHERE action_id = event.stream_id;
                DELETE FROM compliance_results_projection WHERE action_id = event.stream_id;

                -- Re-evaluate compliance for all devices affected by these policies
                FOR v_device_id IN
                    SELECT DISTINCT a.target_id
                    FROM assignments_projection a
                    WHERE a.source_type = 'compliance_policy'
                      AND a.source_id = ANY(v_affected_policies)
                      AND a.target_type = 'device'
                      AND a.is_deleted = FALSE
                    UNION
                    SELECT DISTINCT dgm.device_id
                    FROM assignments_projection a
                    JOIN device_group_members_projection dgm ON dgm.group_id = a.target_id
                    WHERE a.source_type = 'compliance_policy'
                      AND a.source_id = ANY(v_affected_policies)
                      AND a.target_type = 'device_group'
                      AND a.is_deleted = FALSE
                LOOP
                    PERFORM evaluate_device_compliance_policies(v_device_id);
                END LOOP;
            END IF;

        WHEN 'DefinitionCreated' THEN
            IF event.data ? 'action_type' THEN
                INSERT INTO actions_projection (
                    id, name, description, action_type, desired_state,
                    params, timeout_seconds, created_at, updated_at, created_by, projection_version
                ) VALUES (
                    event.stream_id,
                    event.data->>'name',
                    event.data->>'description',
                    COALESCE((event.data->>'action_type')::INTEGER, 0),
                    COALESCE((event.data->>'desired_state')::INTEGER, 0),
                    COALESCE(event.data->'params', '{}'),
                    COALESCE((event.data->>'timeout_seconds')::INTEGER, 300),
                    event.occurred_at,
                    event.occurred_at,
                    event.actor_id,
                    event.sequence_num
                );
            END IF;

        WHEN 'DefinitionRenamed' THEN
            UPDATE actions_projection
            SET name = event.data->>'name',
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'DefinitionDescriptionUpdated' THEN
            UPDATE actions_projection
            SET description = event.data->>'description',
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'DefinitionDeleted' THEN
            UPDATE actions_projection
            SET is_deleted = TRUE,
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- Restore the PL/pgSQL projector for definitions verbatim from
-- migration 012_action_set_definition_schedule (the latest definition,
-- which adds the schedule column and DefinitionScheduleUpdated handler).

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_definition_event(event events) RETURNS void AS $$
BEGIN
    CASE event.event_type
        WHEN 'DefinitionCreated' THEN
            IF NOT (event.data ? 'action_type') THEN
                INSERT INTO definitions_projection (
                    id, name, description, schedule, created_at, updated_at, created_by, projection_version
                ) VALUES (
                    event.stream_id,
                    event.data->>'name',
                    COALESCE(event.data->>'description', ''),
                    COALESCE((event.data->'schedule')::JSONB, '{"interval_hours": 8}'::JSONB),
                    event.occurred_at,
                    event.occurred_at,
                    event.actor_id,
                    event.sequence_num
                );
            END IF;

        WHEN 'DefinitionRenamed' THEN
            UPDATE definitions_projection
            SET name = event.data->>'name',
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'DefinitionDescriptionUpdated' THEN
            UPDATE definitions_projection
            SET description = COALESCE(event.data->>'description', ''),
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'DefinitionScheduleUpdated' THEN
            UPDATE definitions_projection
            SET schedule = COALESCE((event.data->'schedule')::JSONB, '{"interval_hours": 8}'::JSONB),
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'DefinitionMemberAdded' THEN
            INSERT INTO definition_members_projection (
                definition_id, action_set_id, sort_order, added_at, projection_version
            ) VALUES (
                event.stream_id,
                event.data->>'action_set_id',
                COALESCE((event.data->>'sort_order')::INTEGER, 0),
                event.occurred_at,
                event.sequence_num
            ) ON CONFLICT (definition_id, action_set_id) DO NOTHING;

            UPDATE definitions_projection
            SET member_count = (SELECT COUNT(*) FROM definition_members_projection WHERE definition_id = event.stream_id),
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'DefinitionMemberRemoved' THEN
            DELETE FROM definition_members_projection
            WHERE definition_id = event.stream_id AND action_set_id = event.data->>'action_set_id';

            UPDATE definitions_projection
            SET member_count = (SELECT COUNT(*) FROM definition_members_projection WHERE definition_id = event.stream_id),
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'DefinitionMemberReordered' THEN
            UPDATE definition_members_projection
            SET sort_order = COALESCE((event.data->>'sort_order')::INTEGER, 0),
                projection_version = event.sequence_num
            WHERE definition_id = event.stream_id AND action_set_id = event.data->>'action_set_id';

            UPDATE definitions_projection
            SET updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'DefinitionDeleted' THEN
            UPDATE definitions_projection
            SET is_deleted = TRUE,
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
