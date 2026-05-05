-- Replace project_role_event() with a no-op stub. The actual
-- projection logic now lives in projectors.RoleListener (Go,
-- post-commit). The shared project_event() dispatcher trigger
-- still PERFORMs project_role_event(NEW) for every role-stream
-- event; the no-op stub keeps that dispatch quiet (no
-- projection_errors entries) until the dispatcher itself is
-- rewritten to skip stream types with Go projectors.
--
-- Behavioural delta:
--   - Before: PL/pgSQL projector ran inside the AppendEvent
--     transaction. The three event types (Created, Updated,
--     Deleted) and the event commit were atomic. RoleDeleted's
--     two writes (mark deleted + cascade-delete user_roles_projection)
--     were both part of the same transaction.
--   - After: Go listener fires post-commit. RoleDeleted's two
--     writes remain atomic with each other (store.WithTx) but not
--     with the event commit. The role-handler's read-after-write
--     paths (CreateRole/UpdateRole reading back from
--     roles_projection) still see the projection because
--     fireListeners is synchronous — the listener has already run
--     by the time AppendEvent returns.
--
-- Tightening: RoleUpdated and RoleDeleted now have explicit
-- `WHERE projection_version < $N` guards, rejecting stale
-- reconciler replays. The PL/pgSQL version stamped projection_version
-- without a guard.
--
-- See manchtools/power-manage-server#101. Sixth port under the
-- projector-migration pattern (#96 canary, then #97 totp, #98 lps,
-- #99 luks, #100 server_settings, #101 role).
--
-- Refs tracker #107.

-- +goose Up

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_role_event(event events) RETURNS void AS $$
BEGIN
    -- No-op: ported to projectors.RoleListener. See migration
    -- comment + the listener wiring in cmd/control/main.go via
    -- projectors.WireAll.
    NULL;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd


-- +goose Down

-- Restore the original PL/pgSQL projector verbatim from migration 003.

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_role_event(event events) RETURNS void AS $$
BEGIN
    CASE event.event_type
        WHEN 'RoleCreated' THEN
            INSERT INTO roles_projection (
                id, name, description, permissions, is_system,
                created_at, created_by, projection_version
            ) VALUES (
                event.stream_id,
                event.data->>'name',
                COALESCE(event.data->>'description', ''),
                COALESCE(
                    ARRAY(SELECT jsonb_array_elements_text(event.data->'permissions')),
                    '{}'::TEXT[]
                ),
                COALESCE((event.data->>'is_system')::BOOLEAN, FALSE),
                event.occurred_at,
                event.actor_id,
                event.sequence_num
            );

        WHEN 'RoleUpdated' THEN
            UPDATE roles_projection
            SET name = COALESCE(NULLIF(event.data->>'name', ''), name),
                description = COALESCE(event.data->>'description', description),
                permissions = COALESCE(
                    ARRAY(SELECT jsonb_array_elements_text(event.data->'permissions')),
                    permissions
                ),
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'RoleDeleted' THEN
            UPDATE roles_projection
            SET is_deleted = TRUE,
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

            -- Remove all user-role assignments for this role
            DELETE FROM user_roles_projection WHERE role_id = event.stream_id;

        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
