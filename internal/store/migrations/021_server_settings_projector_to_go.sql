-- Replace project_server_settings_event() with a no-op stub. The
-- actual projection logic now lives in
-- projectors.ServerSettingsListener (Go, post-commit). The shared
-- project_event() dispatcher trigger still PERFORMs
-- project_server_settings_event(NEW) for every server_settings-stream
-- event; the no-op stub keeps that dispatch quiet (no
-- projection_errors entries) until the dispatcher itself is
-- rewritten to skip stream types with Go projectors.
--
-- Behavioural delta:
--   - Before: PL/pgSQL projector ran inside the AppendEvent
--     transaction. The COALESCE-based UPDATE and the event commit
--     were atomic.
--   - After: Go listener fires post-commit (single UPDATE; no
--     transaction wrap needed). COALESCE preserves columns the
--     payload omitted; the new `WHERE projection_version < $N`
--     guard rejects stale reconciler replays. The same handler
--     (settings_handler.UpdateServerSettings) reads back from the
--     projection AFTER AppendEvent returns — fireListeners is
--     synchronous, so the read sees the listener's write
--     (read-your-writes preserved).
--
-- See manchtools/power-manage-server#100. Fifth port under the
-- projector-migration pattern (#96, #97, #98, #99, #100).
--
-- Refs tracker #107.

-- +goose Up

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_server_settings_event(event events) RETURNS void AS $$
BEGIN
    -- No-op: ported to projectors.ServerSettingsListener. See
    -- migration comment + the listener wiring in
    -- cmd/control/main.go via projectors.WireAll.
    NULL;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd


-- +goose Down

-- Restore the original PL/pgSQL projector verbatim from migration 003.

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_server_settings_event(event events) RETURNS void AS $$
BEGIN
    CASE event.event_type
        WHEN 'ServerSettingUpdated' THEN
            UPDATE server_settings_projection
            SET user_provisioning_enabled = COALESCE((event.data->>'user_provisioning_enabled')::BOOLEAN, user_provisioning_enabled),
                ssh_access_for_all = COALESCE((event.data->>'ssh_access_for_all')::BOOLEAN, ssh_access_for_all),
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = 'global';
        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
