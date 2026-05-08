-- Replace project_execution_event() with a no-op stub. The actual
-- projection logic now lives in projectors.ExecutionListener (Go,
-- post-commit).
--
-- The shared project_event() dispatcher trigger still PERFORMs
-- project_execution_event(NEW) for every execution-stream event; the
-- no-op stub keeps that dispatch quiet (no plpgsql_projection_errors
-- entries) until the Phase 2 cleanup migration drops every still-
-- PL/pgSQL WHEN clause from the dispatcher.
--
-- Behavioural delta:
--   - Before: PL/pgSQL projector ran inside the AppendEvent
--     transaction. Every execution-stream event (Created, Scheduled,
--     Dispatched, Started, Completed, Failed, TimedOut, Skipped,
--     Cancelled) was atomic with the event commit.
--   - After: Go listener fires post-commit. Every event is a single
--     statement (INSERT or UPDATE) so atomicity is per-event,
--     unchanged. The handler's read-after-write paths
--     (DispatchAction reading back from executions_projection via
--     GetExecutionByID) still see the projection because
--     fireListeners is synchronous — the listener has already run by
--     the time AppendEvent returns.
--
-- Tightening: every UPDATE on executions_projection now carries an
-- explicit `WHERE projection_version < $N` guard, rejecting stale
-- reconciler replays. The PL/pgSQL projector stamped
-- projection_version without a guard, so an out-of-order Completed
-- re-applied after a newer Failed would silently rewind the row's
-- terminal status.
--
-- Asymmetric-guard discipline (per the role + identity_provider +
-- action_set + assignment + user_group + device_group +
-- compliance_policy + compliance + action+definition ports): every
-- UPDATE handler uses :execrows. There is no downstream cascade to
-- gate today (every event is a single-table write against
-- executions_projection), but the SQL guard does the actual stale-
-- replay rejection and the listener-side n == 0 check is preserved
-- for observability and for the regression-test contract.
--
-- ExecutionCancelled is the only handler that layers two guards: the
-- status whitelist (only flip rows still in 'scheduled' or 'pending')
-- AND the projection_version guard. The status whitelist is business
-- logic — a cancel arriving after the dispatch has fired is a
-- documented no-op so the projection doesn't overwrite a real outcome
-- with the cancellation. The version guard is replay safety. Both
-- stay.
--
-- See manchtools/power-manage-server#136. Eighth port under Phase 2
-- of tracker #107's projector-migration pattern.

-- +goose Up

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_execution_event(event events) RETURNS void AS $$
BEGIN
    -- No-op: ported to projectors.ExecutionListener. See migration
    -- comment + the listener wiring in cmd/control/main.go via
    -- projectors.WireAll.
    NULL;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd


-- +goose Down

-- Restore the PL/pgSQL projector for executions verbatim from
-- migration 013_execution_scheduled_cancelled (the latest definition
-- before this port — adds the scheduled / cancelled branches on top
-- of the original 7-event family).

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
