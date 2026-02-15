-- +goose Up

-- Increase batch limit from 100 to 1000 so the evaluation worker can drain
-- larger queues (e.g. after a mass label change) in fewer ticks.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION evaluate_queued_dynamic_groups() RETURNS INTEGER AS $$
DECLARE
    evaluated_count INTEGER := 0;
    queue_record RECORD;
BEGIN
    FOR queue_record IN
        SELECT group_id FROM dynamic_group_evaluation_queue
        ORDER BY queued_at LIMIT 1000
    LOOP
        PERFORM evaluate_dynamic_group(queue_record.group_id);
        evaluated_count := evaluated_count + 1;
    END LOOP;
    RETURN evaluated_count;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- LUKS key storage (projected from LuksKeyRotated events)
CREATE TABLE luks_keys_projection (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id TEXT NOT NULL,
    action_id TEXT NOT NULL,
    device_path TEXT NOT NULL,
    passphrase TEXT NOT NULL,
    rotated_at TIMESTAMPTZ NOT NULL,
    rotation_reason TEXT NOT NULL DEFAULT 'scheduled',
    is_current BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_luks_keys_device ON luks_keys_projection(device_id, is_current);
CREATE INDEX idx_luks_keys_action_device ON luks_keys_projection(action_id, device_id);
CREATE INDEX idx_luks_keys_current ON luks_keys_projection(device_id, action_id, device_path, is_current);

-- LUKS tokens for user passphrase setting (one-time, 15-minute TTL)
CREATE TABLE luks_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id TEXT NOT NULL,
    action_id TEXT NOT NULL,
    token TEXT NOT NULL UNIQUE,
    min_length INTEGER NOT NULL DEFAULT 16,
    complexity INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    used BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX idx_luks_tokens_token ON luks_tokens(token) WHERE NOT used;

-- +goose StatementBegin
-- Projector function for LuksKeyRotated events
CREATE OR REPLACE FUNCTION project_luks_key_event(event events) RETURNS void AS $$
BEGIN
    CASE event.event_type
        WHEN 'LuksKeyRotated' THEN
            -- Mark previous keys as not current for this device+action+device_path
            UPDATE luks_keys_projection
            SET is_current = FALSE
            WHERE device_id = event.data->>'device_id'
              AND action_id = event.data->>'action_id'
              AND device_path = event.data->>'device_path';

            -- Insert new key
            INSERT INTO luks_keys_projection
                (device_id, action_id, device_path, passphrase, rotated_at, rotation_reason)
            VALUES (
                event.data->>'device_id',
                event.data->>'action_id',
                event.data->>'device_path',
                event.data->>'passphrase',
                (event.data->>'rotated_at')::TIMESTAMPTZ,
                COALESCE(event.data->>'rotation_reason', 'scheduled')
            );

            -- Keep only last 3 keys per device+action+device_path
            DELETE FROM luks_keys_projection
            WHERE id NOT IN (
                SELECT id FROM luks_keys_projection
                WHERE device_id = event.data->>'device_id'
                  AND action_id = event.data->>'action_id'
                  AND device_path = event.data->>'device_path'
                ORDER BY rotated_at DESC LIMIT 3
            )
            AND device_id = event.data->>'device_id'
            AND action_id = event.data->>'action_id'
            AND device_path = event.data->>'device_path';
        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- +goose StatementBegin
-- Update master projector to include luks_key stream type
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

        WHEN 'lps_password' THEN
            BEGIN
                PERFORM project_lps_password_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        WHEN 'luks_key' THEN
            BEGIN
                PERFORM project_luks_key_event(NEW);
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
DROP TABLE IF EXISTS luks_tokens;
DROP TABLE IF EXISTS luks_keys_projection;

-- Restore original 100 limit for dynamic group evaluation
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION evaluate_queued_dynamic_groups() RETURNS INTEGER AS $$
DECLARE
    evaluated_count INTEGER := 0;
    queue_record RECORD;
BEGIN
    FOR queue_record IN
        SELECT group_id FROM dynamic_group_evaluation_queue
        ORDER BY queued_at LIMIT 100
    LOOP
        PERFORM evaluate_dynamic_group(queue_record.group_id);
        evaluated_count := evaluated_count + 1;
    END LOOP;
    RETURN evaluated_count;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
