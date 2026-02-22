-- +goose Up

-- TOTP two-factor authentication projection
CREATE TABLE totp_projection (
    user_id TEXT PRIMARY KEY REFERENCES users_projection(id),
    secret_encrypted TEXT NOT NULL,
    verified BOOLEAN NOT NULL DEFAULT FALSE,
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    backup_codes_hash TEXT[] NOT NULL DEFAULT '{}',
    backup_codes_used BOOLEAN[] NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    projection_version BIGINT NOT NULL DEFAULT 0
);

-- Add totp_enabled column to users_projection
ALTER TABLE users_projection ADD COLUMN totp_enabled BOOLEAN NOT NULL DEFAULT FALSE;

-- Projector function for TOTP events
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_totp_event(event events) RETURNS void AS $$
BEGIN
    CASE event.event_type
        WHEN 'TOTPSetupInitiated' THEN
            INSERT INTO totp_projection (
                user_id, secret_encrypted, verified, enabled,
                backup_codes_hash, backup_codes_used,
                created_at, updated_at, projection_version
            ) VALUES (
                event.stream_id,
                event.data->>'secret_encrypted',
                FALSE,
                FALSE,
                ARRAY(SELECT jsonb_array_elements_text(event.data->'backup_codes_hash')),
                ARRAY(SELECT FALSE FROM jsonb_array_elements_text(event.data->'backup_codes_hash')),
                event.occurred_at,
                event.occurred_at,
                event.sequence_num
            )
            ON CONFLICT (user_id) DO UPDATE SET
                secret_encrypted = EXCLUDED.secret_encrypted,
                verified = FALSE,
                enabled = FALSE,
                backup_codes_hash = EXCLUDED.backup_codes_hash,
                backup_codes_used = EXCLUDED.backup_codes_used,
                updated_at = EXCLUDED.updated_at,
                projection_version = EXCLUDED.projection_version;

        WHEN 'TOTPVerified' THEN
            UPDATE totp_projection
            SET verified = TRUE,
                enabled = TRUE,
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE user_id = event.stream_id;

            UPDATE users_projection
            SET totp_enabled = TRUE,
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'TOTPDisabled' THEN
            DELETE FROM totp_projection WHERE user_id = event.stream_id;

            UPDATE users_projection
            SET totp_enabled = FALSE,
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'TOTPBackupCodeUsed' THEN
            UPDATE totp_projection
            SET backup_codes_used[(event.data->>'index')::int + 1] = TRUE,
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE user_id = event.stream_id;

        WHEN 'TOTPBackupCodesRegenerated' THEN
            UPDATE totp_projection
            SET backup_codes_hash = ARRAY(SELECT jsonb_array_elements_text(event.data->'backup_codes_hash')),
                backup_codes_used = ARRAY(SELECT FALSE FROM jsonb_array_elements_text(event.data->'backup_codes_hash')),
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE user_id = event.stream_id;

        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- Add TOTP stream type to the master projector
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

        ELSE
            NULL;
    END CASE;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- Rebuild function for TOTP projection
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION rebuild_totp_projection() RETURNS void AS $$
DECLARE
    event_record events;
BEGIN
    TRUNCATE totp_projection;
    UPDATE users_projection SET totp_enabled = FALSE;
    FOR event_record IN SELECT * FROM events WHERE stream_type = 'totp' ORDER BY sequence_num LOOP
        PERFORM project_totp_event(event_record);
    END LOOP;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- +goose Down

DROP FUNCTION IF EXISTS rebuild_totp_projection;
DROP FUNCTION IF EXISTS project_totp_event;
ALTER TABLE users_projection DROP COLUMN IF EXISTS totp_enabled;
DROP TABLE IF EXISTS totp_projection;
