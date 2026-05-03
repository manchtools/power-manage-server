-- One-shot scheduled dispatch + cancel
--
-- Adds the projection plumbing for the new executions states introduced
-- by the deferred-dispatch feature (manchtools/power-manage-server#57):
--
--   * scheduled — execution row exists, deferred Asynq task is queued
--     to fire at scheduled_for. Created by DispatchAction /
--     DispatchInstantAction when their RunAt option is set.
--   * cancelled — operator pruned a SCHEDULED or PENDING dispatch via
--     CancelExecution before it fired.
--
-- A new `scheduled_for TIMESTAMPTZ NULL` column on executions_projection
-- carries the scheduled timestamp so the UI can show "fires in N hours"
-- on the execution-history list.
--
-- Two new event types are projected:
--   * ExecutionScheduled — sets status='scheduled', scheduled_for=run_at.
--   * ExecutionCancelled — sets status='cancelled', completed_at=event.occurred_at.

-- +goose Up

ALTER TABLE executions_projection
    ADD COLUMN scheduled_for TIMESTAMPTZ NULL;

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

        WHEN 'ExecutionScheduled' THEN
            INSERT INTO executions_projection (
                id, device_id, action_id, action_type, desired_state,
                params, timeout_seconds, status, scheduled_for, created_at,
                created_by_type, created_by_id, projection_version
            ) VALUES (
                event.stream_id,
                event.data->>'device_id',
                COALESCE(event.data->>'action_id', event.data->>'definition_id'),
                (event.data->>'action_type')::INTEGER,
                COALESCE((event.data->>'desired_state')::INTEGER, 0),
                COALESCE(event.data->'params', '{}'),
                COALESCE((event.data->>'timeout_seconds')::INTEGER, 300),
                'scheduled',
                (event.data->>'scheduled_for')::TIMESTAMPTZ,
                event.occurred_at,
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

        WHEN 'ExecutionCancelled' THEN
            -- Cancel only moves a row that's still SCHEDULED or PENDING.
            -- A cancel arriving after the dispatch has fired (RUNNING /
            -- terminal status) is a documented no-op so the projection
            -- doesn't overwrite a real outcome with the cancellation.
            UPDATE executions_projection
            SET status = 'cancelled',
                completed_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id
              AND status IN ('scheduled', 'pending');

        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- +goose Down

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

ALTER TABLE executions_projection DROP COLUMN scheduled_for;
