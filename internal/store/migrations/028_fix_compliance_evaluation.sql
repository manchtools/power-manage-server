-- +goose Up

-- Helper function: re-evaluate compliance for all devices affected by a compliance policy.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION reevaluate_compliance_policy_devices(p_policy_id TEXT) RETURNS void AS $$
DECLARE
    v_device_id TEXT;
BEGIN
    FOR v_device_id IN
        SELECT a.target_id
        FROM assignments_projection a
        WHERE a.source_type = 'compliance_policy'
          AND a.source_id = p_policy_id
          AND a.target_type = 'device'
          AND a.is_deleted = FALSE
        UNION
        SELECT dgm.device_id
        FROM assignments_projection a
        JOIN device_group_members_projection dgm ON dgm.group_id = a.target_id
        WHERE a.source_type = 'compliance_policy'
          AND a.source_id = p_policy_id
          AND a.target_type = 'device_group'
          AND a.is_deleted = FALSE
    LOOP
        PERFORM evaluate_device_compliance_policies(v_device_id);
    END LOOP;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- Update action event projector: clean up compliance data when an action is deleted
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
                is_system
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
                COALESCE((event.data->>'is_system')::BOOLEAN, FALSE)
            );

        WHEN 'ActionRenamed' THEN
            UPDATE actions_projection
            SET name = event.data->>'name',
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

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

-- Update compliance policy event projector: clean up on policy deletion,
-- re-evaluate on rule removal (to update device overall status)
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

-- +goose Down

-- Restore previous compliance policy event projector
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

-- Restore previous action event projector (without compliance cleanup)
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_action_event(event events) RETURNS void AS $$
BEGIN
    CASE event.event_type
        WHEN 'ActionCreated' THEN
            INSERT INTO actions_projection (
                id, name, description, action_type, desired_state,
                params, timeout_seconds, created_at, updated_at, created_by, projection_version,
                is_system
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
                COALESCE((event.data->>'is_system')::BOOLEAN, FALSE)
            );

        WHEN 'ActionRenamed' THEN
            UPDATE actions_projection
            SET name = event.data->>'name',
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

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

DROP FUNCTION IF EXISTS reevaluate_compliance_policy_devices;
