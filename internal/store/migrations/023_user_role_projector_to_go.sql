-- Replace project_user_role_event() with a no-op stub. The actual
-- projection logic now lives in projectors.UserRoleListener (Go,
-- post-commit). The shared project_event() dispatcher trigger
-- still PERFORMs project_user_role_event(NEW) for every user_role-
-- stream event; the no-op stub keeps that dispatch quiet (no
-- projection_errors entries) until the dispatcher itself is
-- rewritten to skip stream types with Go projectors.
--
-- Behavioural delta:
--   - Before: PL/pgSQL projector ran inside the AppendEvent
--     transaction. Both event types (Assigned, Revoked) atomic
--     with the event commit.
--   - After: Go listener fires post-commit. Each event type
--     produces a single statement (INSERT or DELETE), so no tx
--     wrap is needed. The role_handler's idempotency check
--     (`UserHasRole` before emitting Assigned) still works because
--     fireListeners is synchronous — the read sees the listener's
--     write.
--
-- Idempotency under reconciler replays preserved via ON CONFLICT
-- (user_id, role_id) DO NOTHING for Assigned and a plain DELETE for
-- Revoked (silently no-op on a miss). Composite-key fields are
-- explicitly validated at the listener layer so a malformed event
-- can't write a row with empty user_id or role_id.
--
-- See manchtools/power-manage-server#102. Seventh port under the
-- projector-migration pattern.
--
-- Refs tracker #107.

-- +goose Up

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_user_role_event(event events) RETURNS void AS $$
BEGIN
    -- No-op: ported to projectors.UserRoleListener. See migration
    -- comment + the listener wiring in cmd/control/main.go via
    -- projectors.WireAll.
    NULL;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd


-- +goose Down

-- Restore the original PL/pgSQL projector verbatim from migration 003.

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_user_role_event(event events) RETURNS void AS $$
BEGIN
    CASE event.event_type
        WHEN 'UserRoleAssigned' THEN
            INSERT INTO user_roles_projection (
                user_id, role_id, assigned_at, assigned_by, projection_version
            ) VALUES (
                event.data->>'user_id',
                event.data->>'role_id',
                event.occurred_at,
                event.actor_id,
                event.sequence_num
            ) ON CONFLICT (user_id, role_id) DO NOTHING;

        WHEN 'UserRoleRevoked' THEN
            DELETE FROM user_roles_projection
            WHERE user_id = event.data->>'user_id'
              AND role_id = event.data->>'role_id';

        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
