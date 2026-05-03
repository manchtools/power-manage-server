-- Per-group maintenance windows for action dispatch.
--
-- A maintenance_window column is added to device_groups_projection
-- and user_groups_projection. The column holds a JSONB document with
-- the same shape as pm.v1.MaintenanceWindow:
--
--     {"schedule": [{"days": ["mon","tue"], "allow": "22:00-06:00"}, ...]}
--
-- An empty schedule (or NULL column) means "no constraint" — the
-- group does not contribute to the device-side gate. The feature is
-- opt-in: existing rows default to {} and behave exactly as today.
--
-- New event types:
--   - DeviceGroupMaintenanceWindowSet (data: {"maintenance_window": <JSON>})
--   - UserGroupMaintenanceWindowSet   (data: {"maintenance_window": <JSON>})
--
-- The agent enforces the union of these windows in device-local time
-- inside scheduler.runDueActions; the server's only responsibility is
-- to (1) persist them and (2) emit the resolved union over
-- SyncActionsResponse. See manchtools/power-manage-server#58.

-- +goose Up

ALTER TABLE device_groups_projection
    ADD COLUMN maintenance_window JSONB NOT NULL DEFAULT '{}'::JSONB;

ALTER TABLE user_groups_projection
    ADD COLUMN maintenance_window JSONB NOT NULL DEFAULT '{}'::JSONB;

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

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_user_group_event(event events) RETURNS void AS $$
DECLARE
    is_dyn BOOLEAN;
BEGIN
    CASE event.event_type
        WHEN 'UserGroupCreated' THEN
            is_dyn := COALESCE((event.data->>'is_dynamic')::BOOLEAN, FALSE);
            INSERT INTO user_groups_projection (
                id, name, description, member_count,
                created_at, created_by, updated_at, projection_version,
                is_dynamic, dynamic_query
            ) VALUES (
                event.stream_id,
                event.data->>'name',
                COALESCE(event.data->>'description', ''),
                0,
                event.occurred_at,
                event.actor_id,
                event.occurred_at,
                event.sequence_num,
                is_dyn,
                event.data->>'dynamic_query'
            );

            IF is_dyn THEN
                INSERT INTO dynamic_user_group_evaluation_queue (group_id, reason)
                VALUES (event.stream_id, 'group_created')
                ON CONFLICT (group_id) DO UPDATE SET queued_at = clock_timestamp();
            END IF;

        WHEN 'UserGroupUpdated' THEN
            UPDATE user_groups_projection
            SET name = event.data->>'name',
                description = COALESCE(event.data->>'description', description),
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'UserGroupQueryUpdated' THEN
            is_dyn := COALESCE((event.data->>'is_dynamic')::BOOLEAN, FALSE);
            UPDATE user_groups_projection
            SET is_dynamic = is_dyn,
                dynamic_query = event.data->>'dynamic_query',
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

            IF is_dyn THEN
                DELETE FROM user_group_members_projection WHERE group_id = event.stream_id;
                UPDATE user_groups_projection SET member_count = 0 WHERE id = event.stream_id;
                INSERT INTO dynamic_user_group_evaluation_queue (group_id, reason)
                VALUES (event.stream_id, 'query_updated')
                ON CONFLICT (group_id) DO UPDATE SET queued_at = clock_timestamp();
            END IF;

        WHEN 'UserGroupMaintenanceWindowSet' THEN
            UPDATE user_groups_projection
            SET maintenance_window = COALESCE(event.data->'maintenance_window', '{}'::JSONB),
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'UserGroupDeleted' THEN
            DELETE FROM scim_group_mapping_projection WHERE user_group_id = event.stream_id;

            UPDATE user_groups_projection
            SET is_deleted = TRUE,
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

            DELETE FROM user_group_members_projection WHERE group_id = event.stream_id;
            DELETE FROM user_group_roles_projection WHERE group_id = event.stream_id;
            DELETE FROM dynamic_user_group_evaluation_queue WHERE group_id = event.stream_id;

        WHEN 'UserGroupMemberAdded' THEN
            IF NOT EXISTS (
                SELECT 1 FROM user_groups_projection
                WHERE id = event.data->>'group_id' AND is_dynamic = TRUE
            ) THEN
                INSERT INTO user_group_members_projection (
                    group_id, user_id, added_at, added_by, projection_version
                ) VALUES (
                    event.data->>'group_id',
                    event.data->>'user_id',
                    event.occurred_at,
                    event.actor_id,
                    event.sequence_num
                )
                ON CONFLICT (group_id, user_id) DO NOTHING;

                UPDATE user_groups_projection
                SET member_count = member_count + 1,
                    updated_at = event.occurred_at,
                    projection_version = event.sequence_num
                WHERE id = event.data->>'group_id';
            END IF;

        WHEN 'UserGroupMemberRemoved' THEN
            IF NOT EXISTS (
                SELECT 1 FROM user_groups_projection
                WHERE id = event.data->>'group_id' AND is_dynamic = TRUE
            ) THEN
                DELETE FROM user_group_members_projection
                WHERE group_id = event.data->>'group_id'
                  AND user_id = event.data->>'user_id';

                UPDATE user_groups_projection
                SET member_count = GREATEST(member_count - 1, 0),
                    updated_at = event.occurred_at,
                    projection_version = event.sequence_num
                WHERE id = event.data->>'group_id';
            END IF;

        WHEN 'UserGroupRoleAssigned' THEN
            INSERT INTO user_group_roles_projection (
                group_id, role_id, assigned_at, assigned_by, projection_version
            ) VALUES (
                event.data->>'group_id',
                event.data->>'role_id',
                event.occurred_at,
                event.actor_id,
                event.sequence_num
            )
            ON CONFLICT (group_id, role_id) DO NOTHING;

        WHEN 'UserGroupRoleRevoked' THEN
            DELETE FROM user_group_roles_projection
            WHERE group_id = event.data->>'group_id'
              AND role_id = event.data->>'role_id';

        WHEN 'UserGroupMembersRebuilt' THEN
            DELETE FROM user_group_members_projection WHERE group_id = event.stream_id;

            INSERT INTO user_group_members_projection (group_id, user_id, added_at, added_by, projection_version)
            SELECT event.stream_id, uid, event.occurred_at, 'system', event.sequence_num
            FROM jsonb_array_elements_text(event.data->'user_ids') AS uid
            ON CONFLICT (group_id, user_id) DO NOTHING;

            UPDATE user_groups_projection
            SET member_count = COALESCE(jsonb_array_length(event.data->'user_ids'), 0),
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd


-- +goose Down

-- Restore the previous projector bodies (no maintenance_window cases).

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
                event.stream_id, event.data->>'name', COALESCE(event.data->>'description', ''),
                is_dyn, dyn_query, event.occurred_at, event.actor_id, event.sequence_num
            );
            IF is_dyn THEN
                INSERT INTO dynamic_group_evaluation_queue (group_id, queued_at, reason)
                VALUES (event.stream_id, clock_timestamp(), 'group_created')
                ON CONFLICT (group_id) DO UPDATE SET queued_at = clock_timestamp();
            END IF;
        WHEN 'DeviceGroupRenamed' THEN
            UPDATE device_groups_projection SET name = event.data->>'name', projection_version = event.sequence_num WHERE id = event.stream_id;
        WHEN 'DeviceGroupDescriptionUpdated' THEN
            UPDATE device_groups_projection SET description = COALESCE(event.data->>'description', ''), projection_version = event.sequence_num WHERE id = event.stream_id;
        WHEN 'DeviceGroupQueryUpdated' THEN
            is_dyn := COALESCE((event.data->>'is_dynamic')::BOOLEAN, FALSE);
            dyn_query := event.data->>'dynamic_query';
            UPDATE device_groups_projection SET is_dynamic = is_dyn, dynamic_query = dyn_query, projection_version = event.sequence_num WHERE id = event.stream_id;
            IF is_dyn THEN
                DELETE FROM device_group_members_projection WHERE group_id = event.stream_id;
                UPDATE device_groups_projection SET member_count = 0 WHERE id = event.stream_id;
                INSERT INTO dynamic_group_evaluation_queue (group_id, queued_at, reason)
                VALUES (event.stream_id, clock_timestamp(), 'query_updated')
                ON CONFLICT (group_id) DO UPDATE SET queued_at = clock_timestamp();
            END IF;
        WHEN 'DeviceGroupSyncIntervalSet' THEN
            UPDATE device_groups_projection SET sync_interval_minutes = COALESCE((event.data->>'sync_interval_minutes')::INTEGER, 0), projection_version = event.sequence_num WHERE id = event.stream_id;
        WHEN 'DeviceGroupMemberAdded', 'DeviceAddedToGroup' THEN
            IF NOT EXISTS (SELECT 1 FROM device_groups_projection WHERE id = event.stream_id AND is_dynamic = TRUE) THEN
                INSERT INTO device_group_members_projection (group_id, device_id, added_at, projection_version)
                VALUES (event.stream_id, event.data->>'device_id', event.occurred_at, event.sequence_num)
                ON CONFLICT (group_id, device_id) DO NOTHING;
                UPDATE device_groups_projection
                SET member_count = (SELECT COUNT(*) FROM device_group_members_projection WHERE group_id = event.stream_id), projection_version = event.sequence_num
                WHERE id = event.stream_id;
            END IF;
        WHEN 'DeviceGroupMemberRemoved', 'DeviceRemovedFromGroup' THEN
            IF NOT EXISTS (SELECT 1 FROM device_groups_projection WHERE id = event.stream_id AND is_dynamic = TRUE) THEN
                DELETE FROM device_group_members_projection WHERE group_id = event.stream_id AND device_id = event.data->>'device_id';
                UPDATE device_groups_projection
                SET member_count = (SELECT COUNT(*) FROM device_group_members_projection WHERE group_id = event.stream_id), projection_version = event.sequence_num
                WHERE id = event.stream_id;
            END IF;
        WHEN 'DeviceGroupDeleted' THEN
            UPDATE device_groups_projection SET is_deleted = TRUE, projection_version = event.sequence_num WHERE id = event.stream_id;
            DELETE FROM device_group_members_projection WHERE group_id = event.stream_id;
            DELETE FROM dynamic_group_evaluation_queue WHERE group_id = event.stream_id;
        ELSE NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_user_group_event(event events) RETURNS void AS $$
DECLARE
    is_dyn BOOLEAN;
BEGIN
    CASE event.event_type
        WHEN 'UserGroupCreated' THEN
            is_dyn := COALESCE((event.data->>'is_dynamic')::BOOLEAN, FALSE);
            INSERT INTO user_groups_projection (id, name, description, member_count, created_at, created_by, updated_at, projection_version, is_dynamic, dynamic_query)
            VALUES (event.stream_id, event.data->>'name', COALESCE(event.data->>'description', ''), 0, event.occurred_at, event.actor_id, event.occurred_at, event.sequence_num, is_dyn, event.data->>'dynamic_query');
            IF is_dyn THEN
                INSERT INTO dynamic_user_group_evaluation_queue (group_id, reason) VALUES (event.stream_id, 'group_created')
                ON CONFLICT (group_id) DO UPDATE SET queued_at = clock_timestamp();
            END IF;
        WHEN 'UserGroupUpdated' THEN
            UPDATE user_groups_projection SET name = event.data->>'name', description = COALESCE(event.data->>'description', description), updated_at = event.occurred_at, projection_version = event.sequence_num WHERE id = event.stream_id;
        WHEN 'UserGroupQueryUpdated' THEN
            is_dyn := COALESCE((event.data->>'is_dynamic')::BOOLEAN, FALSE);
            UPDATE user_groups_projection SET is_dynamic = is_dyn, dynamic_query = event.data->>'dynamic_query', updated_at = event.occurred_at, projection_version = event.sequence_num WHERE id = event.stream_id;
            IF is_dyn THEN
                DELETE FROM user_group_members_projection WHERE group_id = event.stream_id;
                UPDATE user_groups_projection SET member_count = 0 WHERE id = event.stream_id;
                INSERT INTO dynamic_user_group_evaluation_queue (group_id, reason) VALUES (event.stream_id, 'query_updated')
                ON CONFLICT (group_id) DO UPDATE SET queued_at = clock_timestamp();
            END IF;
        WHEN 'UserGroupDeleted' THEN
            DELETE FROM scim_group_mapping_projection WHERE user_group_id = event.stream_id;
            UPDATE user_groups_projection SET is_deleted = TRUE, updated_at = event.occurred_at, projection_version = event.sequence_num WHERE id = event.stream_id;
            DELETE FROM user_group_members_projection WHERE group_id = event.stream_id;
            DELETE FROM user_group_roles_projection WHERE group_id = event.stream_id;
            DELETE FROM dynamic_user_group_evaluation_queue WHERE group_id = event.stream_id;
        WHEN 'UserGroupMemberAdded' THEN
            IF NOT EXISTS (SELECT 1 FROM user_groups_projection WHERE id = event.data->>'group_id' AND is_dynamic = TRUE) THEN
                INSERT INTO user_group_members_projection (group_id, user_id, added_at, added_by, projection_version)
                VALUES (event.data->>'group_id', event.data->>'user_id', event.occurred_at, event.actor_id, event.sequence_num)
                ON CONFLICT (group_id, user_id) DO NOTHING;
                UPDATE user_groups_projection SET member_count = member_count + 1, updated_at = event.occurred_at, projection_version = event.sequence_num WHERE id = event.data->>'group_id';
            END IF;
        WHEN 'UserGroupMemberRemoved' THEN
            IF NOT EXISTS (SELECT 1 FROM user_groups_projection WHERE id = event.data->>'group_id' AND is_dynamic = TRUE) THEN
                DELETE FROM user_group_members_projection WHERE group_id = event.data->>'group_id' AND user_id = event.data->>'user_id';
                UPDATE user_groups_projection SET member_count = GREATEST(member_count - 1, 0), updated_at = event.occurred_at, projection_version = event.sequence_num WHERE id = event.data->>'group_id';
            END IF;
        WHEN 'UserGroupRoleAssigned' THEN
            INSERT INTO user_group_roles_projection (group_id, role_id, assigned_at, assigned_by, projection_version)
            VALUES (event.data->>'group_id', event.data->>'role_id', event.occurred_at, event.actor_id, event.sequence_num)
            ON CONFLICT (group_id, role_id) DO NOTHING;
        WHEN 'UserGroupRoleRevoked' THEN
            DELETE FROM user_group_roles_projection WHERE group_id = event.data->>'group_id' AND role_id = event.data->>'role_id';
        WHEN 'UserGroupMembersRebuilt' THEN
            DELETE FROM user_group_members_projection WHERE group_id = event.stream_id;
            INSERT INTO user_group_members_projection (group_id, user_id, added_at, added_by, projection_version)
            SELECT event.stream_id, uid, event.occurred_at, 'system', event.sequence_num
            FROM jsonb_array_elements_text(event.data->'user_ids') AS uid
            ON CONFLICT (group_id, user_id) DO NOTHING;
            UPDATE user_groups_projection
            SET member_count = COALESCE(jsonb_array_length(event.data->'user_ids'), 0), updated_at = event.occurred_at, projection_version = event.sequence_num
            WHERE id = event.stream_id;
        ELSE NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

ALTER TABLE user_groups_projection DROP COLUMN maintenance_window;
ALTER TABLE device_groups_projection DROP COLUMN maintenance_window;
