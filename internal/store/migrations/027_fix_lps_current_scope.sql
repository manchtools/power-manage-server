-- +goose Up

-- Fix project_lps_password_event: the UPDATE that marks old passwords as
-- is_current = FALSE was scoped to (device_id, action_id, username). This
-- meant that when a *different* action rotated the same user's password on
-- the same device, the old action's entry stayed is_current = TRUE.
-- Fix: scope by (device_id, username) so only one password per user per
-- device is ever current, regardless of which action produced it.
-- The history cleanup (keep last 3) is also widened to (device_id, username).

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_lps_password_event(event events) RETURNS void AS $$
BEGIN
    CASE event.event_type
        WHEN 'LpsPasswordRotated' THEN
            -- Mark ALL previous passwords as not current for this device+username
            UPDATE lps_passwords_projection
            SET is_current = FALSE
            WHERE device_id = event.data->>'device_id'
              AND username = event.data->>'username';

            -- Insert new password
            INSERT INTO lps_passwords_projection
                (device_id, action_id, username, password, rotated_at, rotation_reason)
            VALUES (
                event.data->>'device_id',
                event.data->>'action_id',
                event.data->>'username',
                event.data->>'password',
                (event.data->>'rotated_at')::TIMESTAMPTZ,
                COALESCE(event.data->>'rotation_reason', 'scheduled')
            );

            -- Keep only last 3 passwords per device+username
            DELETE FROM lps_passwords_projection
            WHERE id NOT IN (
                SELECT id FROM lps_passwords_projection
                WHERE device_id = event.data->>'device_id'
                  AND username = event.data->>'username'
                ORDER BY rotated_at DESC LIMIT 3
            )
            AND device_id = event.data->>'device_id'
            AND username = event.data->>'username';
        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- Replay all lps_password events to fix the is_current flags
DELETE FROM lps_passwords_projection;

-- +goose StatementBegin
DO $$
DECLARE
    evt events%ROWTYPE;
BEGIN
    FOR evt IN SELECT * FROM events WHERE stream_type = 'lps_password' ORDER BY occurred_at ASC
    LOOP
        PERFORM project_lps_password_event(evt);
    END LOOP;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- +goose Down

-- Restore old projector scoped to (device_id, action_id, username)
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_lps_password_event(event events) RETURNS void AS $$
BEGIN
    CASE event.event_type
        WHEN 'LpsPasswordRotated' THEN
            UPDATE lps_passwords_projection
            SET is_current = FALSE
            WHERE device_id = event.data->>'device_id'
              AND action_id = event.data->>'action_id'
              AND username = event.data->>'username';

            INSERT INTO lps_passwords_projection
                (device_id, action_id, username, password, rotated_at, rotation_reason)
            VALUES (
                event.data->>'device_id',
                event.data->>'action_id',
                event.data->>'username',
                event.data->>'password',
                (event.data->>'rotated_at')::TIMESTAMPTZ,
                COALESCE(event.data->>'rotation_reason', 'scheduled')
            );

            DELETE FROM lps_passwords_projection
            WHERE id NOT IN (
                SELECT id FROM lps_passwords_projection
                WHERE device_id = event.data->>'device_id'
                  AND action_id = event.data->>'action_id'
                  AND username = event.data->>'username'
                ORDER BY rotated_at DESC LIMIT 3
            )
            AND device_id = event.data->>'device_id'
            AND action_id = event.data->>'action_id'
            AND username = event.data->>'username';
        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
