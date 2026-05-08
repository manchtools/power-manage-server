-- Replace project_device_group_event() with a no-op stub. The actual
-- projection logic now lives in projectors.DeviceGroupListener (Go,
-- post-commit). The shared project_event() dispatcher trigger still
-- PERFORMs project_device_group_event(NEW) for every device_group-stream
-- event; the no-op stub keeps that dispatch quiet (no
-- plpgsql_projection_errors entries) until the Phase 2 cleanup
-- migration drops every still-PL/pgSQL WHEN clause from the
-- dispatcher.
--
-- Behavioural delta:
--   - Before: PL/pgSQL projector ran inside the AppendEvent
--     transaction. The nine event types (Created, Renamed,
--     DescriptionUpdated, QueryUpdated, SyncIntervalSet,
--     MaintenanceWindowSet, MemberAdded / DeviceAddedToGroup,
--     MemberRemoved / DeviceRemovedFromGroup, Deleted) and their
--     cascades were atomic with the event commit.
--   - After: Go listener fires post-commit. Every multi-write event
--     (Created when dynamic, QueryUpdated when flipping to dynamic,
--     Deleted, MemberAdded / DeviceAddedToGroup, MemberRemoved /
--     DeviceRemovedFromGroup) wraps its writes in store.WithTx so the
--     cascade stays atomic with itself, but not with the event commit.
--     The handler's read-after-write paths (CreateDeviceGroup /
--     AddDeviceToGroup / DeleteDeviceGroup etc. reading back from
--     device_groups_projection) still see the projection because
--     fireListeners is synchronous — the listener has already run by
--     the time AppendEvent returns.
--
-- Tightening: every UPDATE on device_groups_projection (Renamed,
-- DescriptionUpdated, QueryUpdated, SyncIntervalSet,
-- MaintenanceWindowSet, member_count recount, soft-delete) now
-- carries an explicit `WHERE projection_version < $N` guard,
-- rejecting stale reconciler replays. The PL/pgSQL projector stamped
-- projection_version without a guard.
--
-- Asymmetric-guard discipline (per the role + identity_provider +
-- action_set + assignment ports): the guarded SoftDelete uses
-- :execrows, and the listener short-circuits the cascade (member
-- wipe + dynamic_group_evaluation_queue cleanup) when n == 0 —
-- otherwise a stale DeviceGroupDeleted re-applied later would
-- silently nuke a freshly-restored group's members. The same guard
-- gates the QueryUpdated flip-to-dynamic cascade so a stale
-- QueryUpdated cannot wipe a live static group's member list.
--
-- Member mutation guards: DeviceGroupMemberAdded /
-- DeviceAddedToGroup and DeviceGroupMemberRemoved /
-- DeviceRemovedFromGroup both early-out when the parent group is
-- dynamic (mirrors the PL/pgSQL `IF NOT EXISTS (... is_dynamic = TRUE)`
-- guard); the dynamic-query evaluator owns the member set for
-- dynamic groups.
--
-- Dynamic-query engine scope: per #136 the dynamic-query evaluator
-- (evaluate_dynamic_group, evaluate_queued_dynamic_groups,
-- validate_dynamic_query) STAYS in PL/pgSQL until a later phase. The
-- Go listener only persists the query string column + (re-)enqueues
-- the group for evaluation when is_dynamic flips ON; the evaluator
-- itself runs inside Postgres unchanged.
--
-- See manchtools/power-manage-server#136. Fourth port under Phase 2
-- of tracker #107's projector-migration pattern.

-- +goose Up

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_device_group_event(event events) RETURNS void AS $$
BEGIN
    -- No-op: ported to projectors.DeviceGroupListener. See migration
    -- comment + the listener wiring in cmd/control/main.go via
    -- projectors.WireAll.
    NULL;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd


-- +goose Down

-- Restore the PL/pgSQL projector verbatim from migration 014 (the
-- last definition before this port — the body that added the
-- DeviceGroupMaintenanceWindowSet handling on top of the prior body).

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_device_group_event(event events) RETURNS void AS $$
DECLARE
    is_dyn BOOLEAN;
    dyn_query TEXT;
BEGIN
    CASE event.event_type
        WHEN 'DeviceGroupCreated' THEN
            is_dyn := COALESCE((event.data->>'is_dynamic')::BOOLEAN, FALSE);
            dyn_query := event.data->>'dynamic_query';

            INSERT INTO device_groups_projection (
                id, name, description, is_dynamic, dynamic_query,
                created_at, created_by, projection_version
            ) VALUES (
                event.stream_id,
                event.data->>'name',
                COALESCE(event.data->>'description', ''),
                is_dyn,
                dyn_query,
                event.occurred_at,
                event.actor_id,
                event.sequence_num
            );

            IF is_dyn THEN
                INSERT INTO dynamic_group_evaluation_queue (group_id, queued_at, reason)
                VALUES (event.stream_id, clock_timestamp(), 'group_created')
                ON CONFLICT (group_id) DO UPDATE SET queued_at = clock_timestamp();
            END IF;

        WHEN 'DeviceGroupRenamed' THEN
            UPDATE device_groups_projection
            SET name = event.data->>'name',
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'DeviceGroupDescriptionUpdated' THEN
            UPDATE device_groups_projection
            SET description = COALESCE(event.data->>'description', ''),
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'DeviceGroupQueryUpdated' THEN
            is_dyn := COALESCE((event.data->>'is_dynamic')::BOOLEAN, FALSE);
            dyn_query := event.data->>'dynamic_query';

            UPDATE device_groups_projection
            SET is_dynamic = is_dyn,
                dynamic_query = dyn_query,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

            IF is_dyn THEN
                DELETE FROM device_group_members_projection WHERE group_id = event.stream_id;
                UPDATE device_groups_projection SET member_count = 0 WHERE id = event.stream_id;

                INSERT INTO dynamic_group_evaluation_queue (group_id, queued_at, reason)
                VALUES (event.stream_id, clock_timestamp(), 'query_updated')
                ON CONFLICT (group_id) DO UPDATE SET queued_at = clock_timestamp();
            END IF;

        WHEN 'DeviceGroupSyncIntervalSet' THEN
            UPDATE device_groups_projection
            SET sync_interval_minutes = COALESCE((event.data->>'sync_interval_minutes')::INTEGER, 0),
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'DeviceGroupMaintenanceWindowSet' THEN
            UPDATE device_groups_projection
            SET maintenance_window = COALESCE(event.data->'maintenance_window', '{}'::JSONB),
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'DeviceGroupMemberAdded', 'DeviceAddedToGroup' THEN
            IF NOT EXISTS (SELECT 1 FROM device_groups_projection WHERE id = event.stream_id AND is_dynamic = TRUE) THEN
                INSERT INTO device_group_members_projection (
                    group_id, device_id, added_at, projection_version
                ) VALUES (
                    event.stream_id,
                    event.data->>'device_id',
                    event.occurred_at,
                    event.sequence_num
                ) ON CONFLICT (group_id, device_id) DO NOTHING;

                UPDATE device_groups_projection
                SET member_count = (SELECT COUNT(*) FROM device_group_members_projection WHERE group_id = event.stream_id),
                    projection_version = event.sequence_num
                WHERE id = event.stream_id;
            END IF;

        WHEN 'DeviceGroupMemberRemoved', 'DeviceRemovedFromGroup' THEN
            IF NOT EXISTS (SELECT 1 FROM device_groups_projection WHERE id = event.stream_id AND is_dynamic = TRUE) THEN
                DELETE FROM device_group_members_projection
                WHERE group_id = event.stream_id AND device_id = event.data->>'device_id';

                UPDATE device_groups_projection
                SET member_count = (SELECT COUNT(*) FROM device_group_members_projection WHERE group_id = event.stream_id),
                    projection_version = event.sequence_num
                WHERE id = event.stream_id;
            END IF;

        WHEN 'DeviceGroupDeleted' THEN
            UPDATE device_groups_projection
            SET is_deleted = TRUE,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

            DELETE FROM device_group_members_projection WHERE group_id = event.stream_id;
            DELETE FROM dynamic_group_evaluation_queue WHERE group_id = event.stream_id;

        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
