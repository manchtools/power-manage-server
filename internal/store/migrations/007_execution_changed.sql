-- +goose Up
-- Add changed column to executions_projection to track if execution made system changes
ALTER TABLE executions_projection ADD COLUMN IF NOT EXISTS changed BOOLEAN NOT NULL DEFAULT TRUE;

-- Update projection function to handle the changed field
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

-- +goose Down
-- Restore original function without changed field
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
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'ExecutionFailed' THEN
            UPDATE executions_projection
            SET status = 'failed',
                completed_at = COALESCE((event.data->>'completed_at')::TIMESTAMPTZ, event.occurred_at),
                error = event.data->>'error',
                output = event.data->'output',
                duration_ms = (event.data->>'duration_ms')::BIGINT,
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

ALTER TABLE executions_projection DROP COLUMN IF EXISTS changed;
