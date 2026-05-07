-- Replace project_action_set_event() with a no-op stub. The actual
-- projection logic now lives in projectors.ActionSetListener (Go,
-- post-commit). The shared project_event() dispatcher trigger still
-- PERFORMs project_action_set_event(NEW) for every action_set-stream
-- event; the no-op stub keeps that dispatch quiet (no
-- plpgsql_projection_errors entries) until the Phase 2 cleanup
-- migration drops every still-PL/pgSQL WHEN clause from the
-- dispatcher.
--
-- Behavioural delta:
--   - Before: PL/pgSQL projector ran inside the AppendEvent
--     transaction. The eight event types (Created, Renamed,
--     DescriptionUpdated, ScheduleUpdated, MemberAdded,
--     MemberRemoved, MemberReordered, Deleted) and their cascades
--     were atomic with the event commit.
--   - After: Go listener fires post-commit. Every multi-write event
--     (MemberAdded/Removed/Reordered/Deleted) wraps its writes in
--     store.WithTx so the cascade stays atomic with itself, but not
--     with the event commit. The handler's read-after-write paths
--     (CreateActionSet/RenameActionSet/AddActionToSet etc. reading
--     back from action_sets_projection) still see the projection
--     because fireListeners is synchronous — the listener has
--     already run by the time AppendEvent returns.
--
-- Tightening: every UPDATE on action_sets_projection (Renamed,
-- DescriptionUpdated, ScheduleUpdated, member_count recount,
-- updated_at touch, soft-delete) and every UPDATE on
-- action_set_members_projection (sort_order reorder) now has an
-- explicit `WHERE projection_version < $N` guard, rejecting stale
-- reconciler replays. The PL/pgSQL projector stamped
-- projection_version without a guard.
--
-- Asymmetric-guard discipline (per the role + identity_provider
-- ports): the guarded SoftDelete uses :execrows, and the listener
-- short-circuits the cascade (member wipe + parent-definition
-- decrement + definition_members cleanup) when n == 0 — otherwise
-- a stale ActionSetDeleted re-applied later would silently nuke a
-- freshly-restored set's members and decrement live definitions'
-- member_count.
--
-- See manchtools/power-manage-server#136. First port under Phase 2
-- of tracker #107's projector-migration pattern.

-- +goose Up

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_action_set_event(event events) RETURNS void AS $$
BEGIN
    -- No-op: ported to projectors.ActionSetListener. See migration
    -- comment + the listener wiring in cmd/control/main.go via
    -- projectors.WireAll.
    NULL;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd


-- +goose Down

-- Restore the PL/pgSQL projector verbatim from migration 012 (the
-- last definition before this port). Migration 012 added the
-- ScheduleUpdated event + the schedule column to ActionSetCreated;
-- restoring that body is the correct rollback target since 012's
-- shape was the live state immediately before this migration ran.

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_action_set_event(event events) RETURNS void AS $$
BEGIN
    CASE event.event_type
        WHEN 'ActionSetCreated' THEN
            INSERT INTO action_sets_projection (
                id, name, description, schedule, created_at, updated_at, created_by, projection_version
            ) VALUES (
                event.stream_id,
                event.data->>'name',
                COALESCE(event.data->>'description', ''),
                COALESCE((event.data->'schedule')::JSONB, '{"interval_hours": 8}'::JSONB),
                event.occurred_at,
                event.occurred_at,
                event.actor_id,
                event.sequence_num
            );

        WHEN 'ActionSetRenamed' THEN
            UPDATE action_sets_projection
            SET name = event.data->>'name',
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'ActionSetDescriptionUpdated' THEN
            UPDATE action_sets_projection
            SET description = COALESCE(event.data->>'description', ''),
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'ActionSetScheduleUpdated' THEN
            UPDATE action_sets_projection
            SET schedule = COALESCE((event.data->'schedule')::JSONB, '{"interval_hours": 8}'::JSONB),
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'ActionSetMemberAdded' THEN
            INSERT INTO action_set_members_projection (
                set_id, action_id, sort_order, added_at, projection_version
            ) VALUES (
                event.stream_id,
                event.data->>'action_id',
                COALESCE((event.data->>'sort_order')::INTEGER, 0),
                event.occurred_at,
                event.sequence_num
            ) ON CONFLICT (set_id, action_id) DO NOTHING;

            UPDATE action_sets_projection
            SET member_count = (SELECT COUNT(*) FROM action_set_members_projection WHERE set_id = event.stream_id),
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'ActionSetMemberRemoved' THEN
            DELETE FROM action_set_members_projection
            WHERE set_id = event.stream_id AND action_id = event.data->>'action_id';

            UPDATE action_sets_projection
            SET member_count = (SELECT COUNT(*) FROM action_set_members_projection WHERE set_id = event.stream_id),
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'ActionSetMemberReordered' THEN
            UPDATE action_set_members_projection
            SET sort_order = COALESCE((event.data->>'sort_order')::INTEGER, 0),
                projection_version = event.sequence_num
            WHERE set_id = event.stream_id AND action_id = event.data->>'action_id';

            UPDATE action_sets_projection
            SET updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'ActionSetDeleted' THEN
            UPDATE action_sets_projection
            SET is_deleted = TRUE,
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

            DELETE FROM action_set_members_projection WHERE set_id = event.stream_id;

            UPDATE definitions_projection
            SET member_count = member_count - 1
            WHERE id IN (
                SELECT definition_id FROM definition_members_projection WHERE action_set_id = event.stream_id
            );

            DELETE FROM definition_members_projection WHERE action_set_id = event.stream_id;

        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
