-- Replace project_lps_password_event() with a no-op stub. The actual
-- projection logic now lives in projectors.LpsPasswordListener (Go,
-- post-commit). The shared project_event() dispatcher trigger still
-- PERFORMs project_lps_password_event(NEW) for every lps_password-
-- stream event; the no-op stub keeps that dispatch quiet (no
-- projection_errors entries) until the dispatcher itself is rewritten
-- to skip stream types with Go projectors.
--
-- Behavioural delta:
--   - Before: PL/pgSQL projector ran inside the AppendEvent
--     transaction. The three writes (mark previous not-current,
--     insert new, trim history to 3) and the event commit were
--     atomic. A crash anywhere left no partial state.
--   - After: Go listener fires post-commit. Its three writes are
--     wrapped in store.WithTx so they remain atomic with EACH OTHER
--     — the projection never observes the "no current row" gap
--     between the UPDATE-to-FALSE and the INSERT. They are NOT
--     atomic with the event commit; the event lands first, then the
--     listener body runs (within ms). LPS reads are operator-driven
--     ("show me the current password for user X on device Y"), not
--     hot-path RPCs, so the post-commit gap closes before any
--     human-driven query.
--
-- See manchtools/power-manage-server#98. Third port under the
-- projector-migration pattern (#96 canary, #97 totp, #98 lps_password).
--
-- Refs tracker #107.

-- +goose Up

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_lps_password_event(event events) RETURNS void AS $$
BEGIN
    -- No-op: ported to projectors.LpsPasswordListener. See migration
    -- comment + the listener wiring in cmd/control/main.go via
    -- projectors.WireAll.
    NULL;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd


-- +goose Down

-- Restore the original PL/pgSQL projector verbatim from migration 003.

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
