-- +goose Up
-- Remove gateway registration notification from notify_event trigger.
-- Registration is now handled synchronously by the control server RPC,
-- so the pg_notify relay to gateways is no longer needed.

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION notify_event() RETURNS trigger AS $$
DECLARE
    channel TEXT;
    payload TEXT;
BEGIN
    channel := 'events';

    -- Build notification payload based on event type
    CASE
        -- Execution status changes: send lightweight payload (no output data)
        WHEN NEW.event_type IN ('ExecutionCreated', 'ExecutionDispatched', 'ExecutionStarted',
                                'ExecutionCompleted', 'ExecutionFailed', 'ExecutionTimedOut', 'ExecutionSkipped') THEN
            payload := json_build_object(
                'id', NEW.id,
                'sequence_num', NEW.sequence_num,
                'stream_type', NEW.stream_type,
                'stream_id', NEW.stream_id,
                'event_type', NEW.event_type,
                'data', json_build_object(
                    'device_id', NEW.data->>'device_id',
                    'action_id', COALESCE(NEW.data->>'action_id', NEW.data->>'definition_id'),
                    'action_type', NEW.data->>'action_type',
                    'status', CASE NEW.event_type
                        WHEN 'ExecutionCreated' THEN 'pending'
                        WHEN 'ExecutionDispatched' THEN 'dispatched'
                        WHEN 'ExecutionStarted' THEN 'running'
                        WHEN 'ExecutionCompleted' THEN 'success'
                        WHEN 'ExecutionFailed' THEN 'failed'
                        WHEN 'ExecutionTimedOut' THEN 'timeout'
                        WHEN 'ExecutionSkipped' THEN 'skipped'
                    END,
                    'error', NEW.data->>'error',
                    'duration_ms', NEW.data->>'duration_ms'
                ),
                'actor_type', NEW.actor_type,
                'actor_id', NEW.actor_id,
                'occurred_at', NEW.occurred_at
            )::TEXT;

            -- Notify the specific device's agent channel
            IF NEW.data->>'device_id' IS NOT NULL THEN
                PERFORM pg_notify('agent_' || (NEW.data->>'device_id'), payload);
            END IF;

        -- Output chunks: send to device agent only, not to events channel
        WHEN NEW.event_type = 'OutputChunk' THEN
            IF NEW.data->>'device_id' IS NOT NULL THEN
                payload := json_build_object(
                    'stream_id', NEW.stream_id,
                    'event_type', NEW.event_type,
                    'data', NEW.data
                )::TEXT;
                PERFORM pg_notify('agent_' || (NEW.data->>'device_id'), payload);
            END IF;
            -- Don't send output chunks to the events channel
            RETURN NEW;

        -- Device registration: send lightweight event notification
        WHEN NEW.event_type = 'DeviceRegistered' THEN
            payload := json_build_object(
                'id', NEW.id,
                'sequence_num', NEW.sequence_num,
                'stream_type', NEW.stream_type,
                'stream_id', NEW.stream_id,
                'event_type', NEW.event_type,
                'data', json_build_object(
                    'hostname', NEW.data->>'hostname',
                    'registration_token_id', NEW.data->>'registration_token_id'
                ),
                'actor_type', NEW.actor_type,
                'actor_id', NEW.actor_id,
                'occurred_at', NEW.occurred_at
            )::TEXT;

        ELSE
            -- Default: send full event payload
            payload := json_build_object(
                'id', NEW.id,
                'sequence_num', NEW.sequence_num,
                'stream_type', NEW.stream_type,
                'stream_id', NEW.stream_id,
                'event_type', NEW.event_type,
                'data', NEW.data,
                'actor_type', NEW.actor_type,
                'actor_id', NEW.actor_id,
                'occurred_at', NEW.occurred_at
            )::TEXT;
    END CASE;

    -- Notify on the events channel
    PERFORM pg_notify(channel, payload);

    -- Notify agent channel for execution events
    IF NEW.stream_type = 'execution' AND NEW.data->>'device_id' IS NOT NULL THEN
        PERFORM pg_notify('agent_' || (NEW.data->>'device_id'), payload);
    END IF;

    -- Notify UI updates channel for projectable events
    IF NEW.stream_type IN ('user', 'token', 'device', 'action', 'definition',
                            'action_set', 'device_group', 'assignment', 'execution',
                            'user_selection') THEN
        PERFORM pg_notify('ui_updates', json_build_object(
            'stream_type', NEW.stream_type,
            'stream_id', NEW.stream_id,
            'event_type', NEW.event_type
        )::TEXT);
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- +goose Down
-- Restore the gateway notification for DeviceRegistered events.

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION notify_event() RETURNS trigger AS $$
DECLARE
    channel TEXT;
    payload TEXT;
    gateway_channel TEXT;
    gateway_payload TEXT;
BEGIN
    channel := 'events';

    CASE
        WHEN NEW.event_type IN ('ExecutionCreated', 'ExecutionDispatched', 'ExecutionStarted',
                                'ExecutionCompleted', 'ExecutionFailed', 'ExecutionTimedOut', 'ExecutionSkipped') THEN
            payload := json_build_object(
                'id', NEW.id,
                'sequence_num', NEW.sequence_num,
                'stream_type', NEW.stream_type,
                'stream_id', NEW.stream_id,
                'event_type', NEW.event_type,
                'data', json_build_object(
                    'device_id', NEW.data->>'device_id',
                    'action_id', COALESCE(NEW.data->>'action_id', NEW.data->>'definition_id'),
                    'action_type', NEW.data->>'action_type',
                    'status', CASE NEW.event_type
                        WHEN 'ExecutionCreated' THEN 'pending'
                        WHEN 'ExecutionDispatched' THEN 'dispatched'
                        WHEN 'ExecutionStarted' THEN 'running'
                        WHEN 'ExecutionCompleted' THEN 'success'
                        WHEN 'ExecutionFailed' THEN 'failed'
                        WHEN 'ExecutionTimedOut' THEN 'timeout'
                        WHEN 'ExecutionSkipped' THEN 'skipped'
                    END,
                    'error', NEW.data->>'error',
                    'duration_ms', NEW.data->>'duration_ms'
                ),
                'actor_type', NEW.actor_type,
                'actor_id', NEW.actor_id,
                'occurred_at', NEW.occurred_at
            )::TEXT;

            IF NEW.data->>'device_id' IS NOT NULL THEN
                PERFORM pg_notify('agent_' || (NEW.data->>'device_id'), payload);
            END IF;

        WHEN NEW.event_type = 'OutputChunk' THEN
            IF NEW.data->>'device_id' IS NOT NULL THEN
                payload := json_build_object(
                    'stream_id', NEW.stream_id,
                    'event_type', NEW.event_type,
                    'data', NEW.data
                )::TEXT;
                PERFORM pg_notify('agent_' || (NEW.data->>'device_id'), payload);
            END IF;
            RETURN NEW;

        WHEN NEW.event_type = 'DeviceRegistered' THEN
            payload := json_build_object(
                'id', NEW.id,
                'sequence_num', NEW.sequence_num,
                'stream_type', NEW.stream_type,
                'stream_id', NEW.stream_id,
                'event_type', NEW.event_type,
                'data', json_build_object(
                    'hostname', NEW.data->>'hostname',
                    'registration_token_id', NEW.data->>'registration_token_id'
                ),
                'actor_type', NEW.actor_type,
                'actor_id', NEW.actor_id,
                'occurred_at', NEW.occurred_at
            )::TEXT;

            IF NEW.data->>'gateway_id' IS NOT NULL AND NEW.data->>'connection_id' IS NOT NULL THEN
                gateway_channel := 'gateway_' || (NEW.data->>'gateway_id');
                gateway_payload := json_build_object(
                    'type', 'registration_response',
                    'connection_id', NEW.data->>'connection_id',
                    'device_id', NEW.stream_id,
                    'cert_pem', NEW.data->>'cert_pem',
                    'ca_cert_pem', NEW.data->>'ca_cert_pem'
                )::TEXT;
                PERFORM pg_notify(gateway_channel, gateway_payload);
            END IF;

        ELSE
            payload := json_build_object(
                'id', NEW.id,
                'sequence_num', NEW.sequence_num,
                'stream_type', NEW.stream_type,
                'stream_id', NEW.stream_id,
                'event_type', NEW.event_type,
                'data', NEW.data,
                'actor_type', NEW.actor_type,
                'actor_id', NEW.actor_id,
                'occurred_at', NEW.occurred_at
            )::TEXT;
    END CASE;

    -- Notify on the events channel
    PERFORM pg_notify(channel, payload);

    -- Notify agent channel for execution events
    IF NEW.stream_type = 'execution' AND NEW.data->>'device_id' IS NOT NULL THEN
        PERFORM pg_notify('agent_' || (NEW.data->>'device_id'), payload);
    END IF;

    -- Notify UI updates channel for projectable events
    IF NEW.stream_type IN ('user', 'token', 'device', 'action', 'definition',
                            'action_set', 'device_group', 'assignment', 'execution',
                            'user_selection') THEN
        PERFORM pg_notify('ui_updates', json_build_object(
            'stream_type', NEW.stream_type,
            'stream_id', NEW.stream_id,
            'event_type', NEW.event_type
        )::TEXT);
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
