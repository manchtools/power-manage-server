-- +goose Up

-- Compliance policies projection
CREATE TABLE compliance_policies_projection (
    id TEXT PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    rule_count INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ,
    created_by TEXT NOT NULL DEFAULT '',
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
    projection_version BIGINT NOT NULL DEFAULT 0
);

-- Rules within a compliance policy
CREATE TABLE compliance_policy_rules_projection (
    policy_id TEXT NOT NULL,
    action_id TEXT NOT NULL,
    action_name TEXT NOT NULL DEFAULT '',
    grace_period_hours INTEGER NOT NULL DEFAULT 0,
    added_at TIMESTAMPTZ,
    projection_version BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (policy_id, action_id)
);
CREATE INDEX idx_compliance_policy_rules_action ON compliance_policy_rules_projection (action_id);

-- Per-device, per-policy-rule evaluation state
CREATE TABLE compliance_policy_evaluation_projection (
    device_id TEXT NOT NULL,
    policy_id TEXT NOT NULL,
    action_id TEXT NOT NULL,
    compliant BOOLEAN NOT NULL DEFAULT FALSE,
    first_failed_at TIMESTAMPTZ,
    status INTEGER NOT NULL DEFAULT 0,
    checked_at TIMESTAMPTZ,
    projection_version BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (device_id, policy_id, action_id)
);
CREATE INDEX idx_compliance_eval_device ON compliance_policy_evaluation_projection (device_id);
CREATE INDEX idx_compliance_eval_policy ON compliance_policy_evaluation_projection (policy_id);

-- Compliance policy event projector
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_compliance_policy_event(event events) RETURNS void AS $$
BEGIN
    CASE event.event_type
        WHEN 'CompliancePolicyCreated' THEN
            INSERT INTO compliance_policies_projection (
                id, name, description, created_at, created_by, projection_version
            ) VALUES (
                event.stream_id,
                event.data->>'name',
                COALESCE(event.data->>'description', ''),
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

            -- Clean up evaluation entries for deleted policy
            DELETE FROM compliance_policy_evaluation_projection
            WHERE policy_id = event.stream_id;

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

            -- Clean up evaluation entries for this rule
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

-- Evaluate compliance policies for a device (called after compliance results update)
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION evaluate_device_compliance_policies(p_device_id TEXT) RETURNS void AS $$
DECLARE
    v_rule RECORD;
    v_result RECORD;
    v_rule_status INTEGER;
    v_has_policies BOOLEAN := FALSE;
    v_all_compliant BOOLEAN := TRUE;
    v_any_in_grace BOOLEAN := FALSE;
    v_any_non_compliant BOOLEAN := FALSE;
    v_total INTEGER := 0;
    v_passing INTEGER := 0;
    v_overall_status INTEGER;
    v_existing_first_failed TIMESTAMPTZ;
BEGIN
    -- Iterate over all rules from all policies assigned to this device
    FOR v_rule IN
        SELECT r.policy_id, r.action_id, r.grace_period_hours
        FROM compliance_policy_rules_projection r
        JOIN compliance_policies_projection p ON p.id = r.policy_id AND p.is_deleted = FALSE
        JOIN assignments_projection a ON a.source_type = 'compliance_policy'
            AND a.source_id = r.policy_id AND a.is_deleted = FALSE
        WHERE (
            (a.target_type = 'device' AND a.target_id = p_device_id)
            OR (a.target_type = 'device_group' AND a.target_id IN (
                SELECT group_id FROM device_group_members_projection
                WHERE device_id = p_device_id
            ))
        )
    LOOP
        v_has_policies := TRUE;
        v_total := v_total + 1;

        -- Look up the latest compliance result for this action on this device
        SELECT compliant, checked_at
        INTO v_result
        FROM compliance_results_projection
        WHERE device_id = p_device_id AND action_id = v_rule.action_id;

        IF NOT FOUND THEN
            -- No result yet: unknown
            v_rule_status := 0; -- UNKNOWN
            v_all_compliant := FALSE;

            INSERT INTO compliance_policy_evaluation_projection (
                device_id, policy_id, action_id, compliant, first_failed_at,
                status, checked_at, projection_version
            ) VALUES (
                p_device_id, v_rule.policy_id, v_rule.action_id,
                FALSE, NULL, 0, NULL, 0
            ) ON CONFLICT (device_id, policy_id, action_id) DO UPDATE SET
                compliant = FALSE,
                status = 0,
                projection_version = 0;

        ELSIF v_result.compliant THEN
            -- Compliant: clear first_failed_at
            v_rule_status := 1; -- COMPLIANT
            v_passing := v_passing + 1;

            INSERT INTO compliance_policy_evaluation_projection (
                device_id, policy_id, action_id, compliant, first_failed_at,
                status, checked_at, projection_version
            ) VALUES (
                p_device_id, v_rule.policy_id, v_rule.action_id,
                TRUE, NULL, 1, v_result.checked_at, 0
            ) ON CONFLICT (device_id, policy_id, action_id) DO UPDATE SET
                compliant = TRUE,
                first_failed_at = NULL,
                status = 1,
                checked_at = v_result.checked_at;

        ELSE
            -- Non-compliant: check grace period
            SELECT first_failed_at INTO v_existing_first_failed
            FROM compliance_policy_evaluation_projection
            WHERE device_id = p_device_id
              AND policy_id = v_rule.policy_id
              AND action_id = v_rule.action_id;

            IF v_existing_first_failed IS NULL THEN
                -- First failure: record timestamp
                v_existing_first_failed := NOW();
            END IF;

            IF v_rule.grace_period_hours > 0
               AND (NOW() - v_existing_first_failed) < (v_rule.grace_period_hours || ' hours')::INTERVAL
            THEN
                -- Within grace period
                v_rule_status := 3; -- IN_GRACE_PERIOD
                v_any_in_grace := TRUE;
            ELSE
                -- Past grace period (or no grace period)
                v_rule_status := 2; -- NON_COMPLIANT
                v_any_non_compliant := TRUE;
                v_all_compliant := FALSE;
            END IF;

            INSERT INTO compliance_policy_evaluation_projection (
                device_id, policy_id, action_id, compliant, first_failed_at,
                status, checked_at, projection_version
            ) VALUES (
                p_device_id, v_rule.policy_id, v_rule.action_id,
                FALSE, v_existing_first_failed, v_rule_status,
                v_result.checked_at, 0
            ) ON CONFLICT (device_id, policy_id, action_id) DO UPDATE SET
                compliant = FALSE,
                first_failed_at = COALESCE(
                    compliance_policy_evaluation_projection.first_failed_at,
                    v_existing_first_failed
                ),
                status = v_rule_status,
                checked_at = v_result.checked_at;
        END IF;
    END LOOP;

    -- If no policies assigned, fall back to existing simple compliance
    IF NOT v_has_policies THEN
        PERFORM recalculate_device_compliance(p_device_id);
        RETURN;
    END IF;

    -- Compute overall device status
    IF v_any_non_compliant THEN
        v_overall_status := 2; -- NON_COMPLIANT
    ELSIF v_any_in_grace THEN
        v_overall_status := 3; -- IN_GRACE_PERIOD
    ELSIF v_all_compliant AND v_total > 0 THEN
        v_overall_status := 1; -- COMPLIANT
    ELSE
        v_overall_status := 0; -- UNKNOWN
    END IF;

    UPDATE devices_projection SET
        compliance_status = v_overall_status,
        compliance_checked_at = NOW(),
        compliance_total = v_total,
        compliance_passing = v_passing
    WHERE id = p_device_id;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- Update compliance event projector to use policy evaluation
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
                event.id
            )
            ON CONFLICT (device_id, action_id) DO UPDATE SET
                action_name = COALESCE(event.data->>'action_name', compliance_results_projection.action_name),
                compliant = COALESCE((event.data->>'compliant')::boolean, false),
                detection_output = event.data->'detection_output',
                checked_at = event.occurred_at,
                projection_version = event.id;

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

-- Update project_event to route compliance_policy events
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_event() RETURNS trigger AS $$
BEGIN
    CASE NEW.stream_type
        WHEN 'user' THEN
            BEGIN
                PERFORM project_user_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        WHEN 'token' THEN
            BEGIN
                PERFORM project_token_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        WHEN 'device' THEN
            BEGIN
                PERFORM project_device_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        WHEN 'action' THEN
            BEGIN
                PERFORM project_action_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        WHEN 'definition' THEN
            BEGIN
                PERFORM project_action_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, 'definition->action', SQLERRM);
            END;

            BEGIN
                PERFORM project_definition_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, 'definition->definition', SQLERRM);
            END;

        WHEN 'action_set' THEN
            BEGIN
                PERFORM project_action_set_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        WHEN 'device_group' THEN
            BEGIN
                PERFORM project_device_group_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        WHEN 'assignment' THEN
            BEGIN
                PERFORM project_assignment_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        WHEN 'execution' THEN
            BEGIN
                PERFORM project_execution_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        WHEN 'user_selection' THEN
            BEGIN
                PERFORM project_user_selection_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        WHEN 'role' THEN
            BEGIN
                PERFORM project_role_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        WHEN 'user_role' THEN
            BEGIN
                PERFORM project_user_role_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        WHEN 'totp' THEN
            BEGIN
                PERFORM project_totp_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        WHEN 'user_group' THEN
            BEGIN
                PERFORM project_user_group_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        WHEN 'identity_provider' THEN
            BEGIN
                PERFORM project_identity_provider_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        WHEN 'scim_group_mapping' THEN
            BEGIN
                PERFORM project_scim_group_mapping_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        WHEN 'compliance' THEN
            BEGIN
                PERFORM project_compliance_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        WHEN 'compliance_policy' THEN
            BEGIN
                PERFORM project_compliance_policy_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        ELSE
            NULL;
    END CASE;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- Restore execution projector (unchanged, but required since project_event is recreated)
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_execution_event(event events) RETURNS void AS $$
BEGIN
    CASE event.event_type
        WHEN 'ExecutionCreated' THEN
            INSERT INTO executions_projection (
                id, device_id, action_id, action_type, desired_state,
                params, timeout_seconds, status, created_at,
                created_by_type, created_by_id, projection_version
            ) VALUES (
                event.stream_id,
                event.data->>'device_id',
                COALESCE(event.data->>'action_id', event.data->>'definition_id'),
                (event.data->>'action_type')::INTEGER,
                COALESCE((event.data->>'desired_state')::INTEGER, 0),
                COALESCE(event.data->'params', '{}'),
                COALESCE((event.data->>'timeout_seconds')::INTEGER, 300),
                'pending',
                COALESCE((event.data->>'executed_at')::TIMESTAMPTZ, event.occurred_at),
                event.actor_type,
                event.actor_id,
                event.sequence_num
            );

        WHEN 'ExecutionDispatched' THEN
            UPDATE executions_projection
            SET status = 'dispatched',
                dispatched_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'ExecutionStarted' THEN
            UPDATE executions_projection
            SET status = 'running',
                started_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'ExecutionCompleted' THEN
            UPDATE executions_projection
            SET status = 'success',
                completed_at = COALESCE((event.data->>'completed_at')::TIMESTAMPTZ, event.occurred_at),
                output = event.data->'output',
                duration_ms = (event.data->>'duration_ms')::BIGINT,
                changed = COALESCE((event.data->>'changed')::BOOLEAN, TRUE),
                compliant = COALESCE((event.data->>'compliant')::BOOLEAN, FALSE),
                detection_output = event.data->'detection_output',
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'ExecutionFailed' THEN
            UPDATE executions_projection
            SET status = 'failed',
                completed_at = COALESCE((event.data->>'completed_at')::TIMESTAMPTZ, event.occurred_at),
                error = event.data->>'error',
                output = event.data->'output',
                duration_ms = (event.data->>'duration_ms')::BIGINT,
                changed = COALESCE((event.data->>'changed')::BOOLEAN, TRUE),
                compliant = COALESCE((event.data->>'compliant')::BOOLEAN, FALSE),
                detection_output = event.data->'detection_output',
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'ExecutionTimedOut' THEN
            UPDATE executions_projection
            SET status = 'timeout',
                completed_at = COALESCE((event.data->>'completed_at')::TIMESTAMPTZ, event.occurred_at),
                error = event.data->>'error',
                output = event.data->'output',
                duration_ms = (event.data->>'duration_ms')::BIGINT,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'ExecutionSkipped' THEN
            UPDATE executions_projection
            SET status = 'skipped',
                completed_at = event.occurred_at,
                error = event.data->>'reason',
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- +goose Down
DROP TABLE IF EXISTS compliance_policy_evaluation_projection;
DROP TABLE IF EXISTS compliance_policy_rules_projection;
DROP TABLE IF EXISTS compliance_policies_projection;
DROP FUNCTION IF EXISTS project_compliance_policy_event;
DROP FUNCTION IF EXISTS evaluate_device_compliance_policies;

-- Restore original compliance event projector (without policy evaluation)
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
                event.id
            )
            ON CONFLICT (device_id, action_id) DO UPDATE SET
                action_name = COALESCE(event.data->>'action_name', compliance_results_projection.action_name),
                compliant = COALESCE((event.data->>'compliant')::boolean, false),
                detection_output = event.data->'detection_output',
                checked_at = event.occurred_at,
                projection_version = event.id;

            PERFORM recalculate_device_compliance(event.data->>'device_id');

        WHEN 'ComplianceResultRemoved' THEN
            DELETE FROM compliance_results_projection
            WHERE device_id = event.data->>'device_id'
              AND action_id = event.data->>'action_id';

            PERFORM recalculate_device_compliance(event.data->>'device_id');

        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- Restore project_event without compliance_policy case (from 017_compliance.sql)
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_event() RETURNS trigger AS $$
BEGIN
    CASE NEW.stream_type
        WHEN 'user' THEN
            BEGIN
                PERFORM project_user_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        WHEN 'token' THEN
            BEGIN
                PERFORM project_token_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        WHEN 'device' THEN
            BEGIN
                PERFORM project_device_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        WHEN 'action' THEN
            BEGIN
                PERFORM project_action_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        WHEN 'definition' THEN
            BEGIN
                PERFORM project_action_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, 'definition->action', SQLERRM);
            END;

            BEGIN
                PERFORM project_definition_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, 'definition->definition', SQLERRM);
            END;

        WHEN 'action_set' THEN
            BEGIN
                PERFORM project_action_set_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        WHEN 'device_group' THEN
            BEGIN
                PERFORM project_device_group_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        WHEN 'assignment' THEN
            BEGIN
                PERFORM project_assignment_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        WHEN 'execution' THEN
            BEGIN
                PERFORM project_execution_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        WHEN 'user_selection' THEN
            BEGIN
                PERFORM project_user_selection_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        WHEN 'role' THEN
            BEGIN
                PERFORM project_role_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        WHEN 'user_role' THEN
            BEGIN
                PERFORM project_user_role_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        WHEN 'totp' THEN
            BEGIN
                PERFORM project_totp_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        WHEN 'user_group' THEN
            BEGIN
                PERFORM project_user_group_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        WHEN 'identity_provider' THEN
            BEGIN
                PERFORM project_identity_provider_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        WHEN 'scim_group_mapping' THEN
            BEGIN
                PERFORM project_scim_group_mapping_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        WHEN 'compliance' THEN
            BEGIN
                PERFORM project_compliance_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        ELSE
            NULL;
    END CASE;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
