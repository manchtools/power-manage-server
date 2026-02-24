-- +goose Up

-- Compliance results projection: stores the latest detection result per device per action
CREATE TABLE compliance_results_projection (
    device_id TEXT NOT NULL,
    action_id TEXT NOT NULL,
    action_name TEXT NOT NULL DEFAULT '',
    compliant BOOLEAN NOT NULL DEFAULT FALSE,
    detection_output JSONB,
    checked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    projection_version BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (device_id, action_id)
);
CREATE INDEX idx_compliance_device ON compliance_results_projection (device_id);

-- Add compliance summary columns to devices
ALTER TABLE devices_projection
  ADD COLUMN compliance_status INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN compliance_checked_at TIMESTAMPTZ,
  ADD COLUMN compliance_total INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN compliance_passing INTEGER NOT NULL DEFAULT 0;

-- Add compliance fields to executions
ALTER TABLE executions_projection
  ADD COLUMN compliant BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN detection_output JSONB;

-- Compliance projector function
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

            -- Recalculate device compliance summary
            PERFORM recalculate_device_compliance(event.data->>'device_id');

        WHEN 'ComplianceResultRemoved' THEN
            DELETE FROM compliance_results_projection
            WHERE device_id = event.data->>'device_id'
              AND action_id = event.data->>'action_id';

            -- Recalculate device compliance summary
            PERFORM recalculate_device_compliance(event.data->>'device_id');

        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- Helper to recalculate device compliance summary from its checks
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION recalculate_device_compliance(p_device_id TEXT) RETURNS void AS $$
DECLARE
    v_total INTEGER;
    v_passing INTEGER;
    v_status INTEGER;
BEGIN
    SELECT COUNT(*), COUNT(*) FILTER (WHERE compliant = TRUE)
    INTO v_total, v_passing
    FROM compliance_results_projection
    WHERE device_id = p_device_id;

    IF v_total = 0 THEN
        v_status := 0; -- UNKNOWN
    ELSIF v_passing = v_total THEN
        v_status := 1; -- COMPLIANT
    ELSE
        v_status := 2; -- NON_COMPLIANT
    END IF;

    UPDATE devices_projection SET
        compliance_status = v_status,
        compliance_checked_at = NOW(),
        compliance_total = v_total,
        compliance_passing = v_passing
    WHERE id = p_device_id;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- Update execution projector to store compliance fields
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

-- Update project_event to route compliance events
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

-- +goose Down
DROP TABLE IF EXISTS compliance_results_projection;
ALTER TABLE devices_projection
  DROP COLUMN IF EXISTS compliance_status,
  DROP COLUMN IF EXISTS compliance_checked_at,
  DROP COLUMN IF EXISTS compliance_total,
  DROP COLUMN IF EXISTS compliance_passing;
ALTER TABLE executions_projection
  DROP COLUMN IF EXISTS compliant,
  DROP COLUMN IF EXISTS detection_output;
DROP FUNCTION IF EXISTS project_compliance_event;
DROP FUNCTION IF EXISTS recalculate_device_compliance;

-- Restore project_event without compliance case (from 012_scim.sql)
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

        ELSE
            NULL;
    END CASE;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
