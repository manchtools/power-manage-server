-- Replace project_assignment_event() with a no-op stub. The actual
-- projection logic now lives in projectors.AssignmentListener (Go,
-- post-commit). The shared project_event() dispatcher trigger still
-- PERFORMs project_assignment_event(NEW) for every assignment-stream
-- event; the no-op stub keeps that dispatch quiet (no
-- plpgsql_projection_errors entries) until the Phase 2 cleanup
-- migration drops every still-PL/pgSQL WHEN clause from the
-- dispatcher.
--
-- Behavioural delta:
--   - Before: PL/pgSQL projector ran inside the AppendEvent
--     transaction. The four event types (Created, ModeChanged,
--     SortOrderChanged, Deleted) and the compliance cascade for
--     compliance_policy-source assignments were atomic with the event
--     commit.
--   - After: Go listener fires post-commit. AssignmentCreated and
--     AssignmentDeleted (the cascade-bearing events) wrap their writes
--     + the compliance cascade in store.WithTx so the cascade stays
--     atomic with itself, but not with the event commit. The handler's
--     read-after-write paths (CreateAssignment / DeleteAssignment
--     reading back from assignments_projection) still see the
--     projection because fireListeners is synchronous — the listener
--     has already run by the time AppendEvent returns.
--
-- Tightening: every UPDATE on assignments_projection (mode change,
-- sort-order change, soft-delete) and the ON CONFLICT DO UPDATE branch
-- of AssignmentCreated now carries an explicit
-- `WHERE projection_version < $N` guard, rejecting stale reconciler
-- replays. The PL/pgSQL projector stamped projection_version without a
-- guard.
--
-- Asymmetric-guard discipline (per the role + identity_provider +
-- action_set ports): the guarded SoftDelete uses RETURNING so
-- "no rows" surfaces as pgx.ErrNoRows, and the listener short-circuits
-- the compliance cascade on that signal. Same for the conditional
-- UPDATE branch of AssignmentCreated, which uses :execrows + n == 0
-- short-circuit. Otherwise a stale event re-applied later would
-- re-evaluate compliance against a fresher row the listener wasn't
-- allowed to write, leaving compliance_policy_evaluation_projection
-- inconsistent with the live assignment state.
--
-- Compliance cascade scope: the listener invokes the existing
-- evaluate_device_compliance_policies() PL/pgSQL function via the
-- typed sqlc shim EvaluateDeviceCompliancePolicies. Compliance is
-- deferred to a later phase of #136; until that ports, the cascade
-- behaviour is preserved verbatim by routing through PL/pgSQL.
--
-- See manchtools/power-manage-server#137. Second port under Phase 2
-- of tracker #107's projector-migration pattern.

-- +goose Up

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_assignment_event(event events) RETURNS void AS $$
BEGIN
    -- No-op: ported to projectors.AssignmentListener. See migration
    -- comment + the listener wiring in cmd/control/main.go via
    -- projectors.WireAll.
    NULL;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd


-- +goose Down

-- Restore the PL/pgSQL projector verbatim from migration 002 (the
-- last definition before this port — the "FINAL from 001: updated to
-- trigger compliance evaluation on policy assignment changes" body).

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_assignment_event(event events) RETURNS void AS $$
DECLARE
    v_source_type TEXT;
    v_source_id TEXT;
    v_target_type TEXT;
    v_target_id TEXT;
    v_device_id TEXT;
BEGIN
    CASE event.event_type
        WHEN 'AssignmentCreated' THEN
            INSERT INTO assignments_projection (
                id, source_type, source_id, target_type, target_id,
                sort_order, mode, created_at, created_by, projection_version
            ) VALUES (
                event.stream_id,
                event.data->>'source_type',
                event.data->>'source_id',
                event.data->>'target_type',
                event.data->>'target_id',
                COALESCE((event.data->>'sort_order')::INTEGER, 0),
                COALESCE((event.data->>'mode')::INTEGER, 0),
                event.occurred_at,
                event.actor_id,
                event.sequence_num
            ) ON CONFLICT (source_type, source_id, target_type, target_id) DO UPDATE
            SET is_deleted = FALSE,
                sort_order = COALESCE((event.data->>'sort_order')::INTEGER, 0),
                mode = COALESCE((event.data->>'mode')::INTEGER, 0),
                projection_version = event.sequence_num;

            -- Trigger compliance evaluation when a compliance policy is assigned
            IF event.data->>'source_type' = 'compliance_policy' THEN
                IF event.data->>'target_type' = 'device' THEN
                    PERFORM evaluate_device_compliance_policies(event.data->>'target_id');
                ELSIF event.data->>'target_type' = 'device_group' THEN
                    FOR v_device_id IN
                        SELECT device_id FROM device_group_members_projection
                        WHERE group_id = event.data->>'target_id'
                    LOOP
                        PERFORM evaluate_device_compliance_policies(v_device_id);
                    END LOOP;
                END IF;
            END IF;

        WHEN 'AssignmentModeChanged' THEN
            UPDATE assignments_projection
            SET mode = COALESCE((event.data->>'mode')::INTEGER, 0),
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'AssignmentDeleted' THEN
            -- Look up assignment details before soft-deleting (event data is empty)
            SELECT source_type, source_id, target_type, target_id
            INTO v_source_type, v_source_id, v_target_type, v_target_id
            FROM assignments_projection
            WHERE id = event.stream_id;

            UPDATE assignments_projection
            SET is_deleted = TRUE,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

            -- Re-evaluate compliance when a compliance policy is unassigned
            IF v_source_type = 'compliance_policy' THEN
                IF v_target_type = 'device' THEN
                    -- Clean up evaluation entries for this policy on this device
                    DELETE FROM compliance_policy_evaluation_projection
                    WHERE device_id = v_target_id AND policy_id = v_source_id;
                    PERFORM evaluate_device_compliance_policies(v_target_id);
                ELSIF v_target_type = 'device_group' THEN
                    FOR v_device_id IN
                        SELECT device_id FROM device_group_members_projection
                        WHERE group_id = v_target_id
                    LOOP
                        DELETE FROM compliance_policy_evaluation_projection
                        WHERE device_id = v_device_id AND policy_id = v_source_id;
                        PERFORM evaluate_device_compliance_policies(v_device_id);
                    END LOOP;
                END IF;
            END IF;

        WHEN 'AssignmentSortOrderChanged' THEN
            UPDATE assignments_projection
            SET sort_order = COALESCE((event.data->>'sort_order')::INTEGER, 0),
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
