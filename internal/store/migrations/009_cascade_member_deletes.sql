-- +goose Up
-- Migration to add cascading deletes:
-- 1. When an action is deleted, remove it from all action sets
-- 2. When an action set is deleted, remove it from all definitions

-- +goose StatementBegin
-- Update project_action_event to cascade delete to action_set_members_projection
CREATE OR REPLACE FUNCTION project_action_event(event events) RETURNS void AS $$
BEGIN
    CASE event.event_type
        WHEN 'ActionCreated' THEN
            INSERT INTO actions_projection (
                id, name, description, action_type,
                params, timeout_seconds, created_at, created_by, projection_version
            ) VALUES (
                event.stream_id,
                event.data->>'name',
                event.data->>'description',
                COALESCE((event.data->>'action_type')::INTEGER, 0),
                COALESCE(event.data->'params', '{}'),
                COALESCE((event.data->>'timeout_seconds')::INTEGER, 300),
                event.occurred_at,
                event.actor_id,
                event.sequence_num
            );

        WHEN 'ActionRenamed' THEN
            UPDATE actions_projection
            SET name = event.data->>'name',
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'ActionDescriptionUpdated' THEN
            UPDATE actions_projection
            SET description = event.data->>'description',
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'ActionParamsUpdated' THEN
            UPDATE actions_projection
            SET params = COALESCE(event.data->'params', params),
                timeout_seconds = COALESCE((event.data->>'timeout_seconds')::INTEGER, timeout_seconds),
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'ActionDeleted' THEN
            UPDATE actions_projection
            SET is_deleted = TRUE,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

            -- Cascade: Update member counts for affected action sets
            UPDATE action_sets_projection
            SET member_count = member_count - 1
            WHERE id IN (
                SELECT set_id FROM action_set_members_projection WHERE action_id = event.stream_id
            );

            -- Cascade: Remove action from all action sets
            DELETE FROM action_set_members_projection WHERE action_id = event.stream_id;

        -- Legacy single-action definition events (backward compatibility)
        WHEN 'DefinitionCreated' THEN
            -- Only handle old-style definitions that have action_type
            IF event.data ? 'action_type' THEN
                INSERT INTO actions_projection (
                    id, name, description, action_type,
                    params, timeout_seconds, created_at, created_by, projection_version
                ) VALUES (
                    event.stream_id,
                    event.data->>'name',
                    event.data->>'description',
                    COALESCE((event.data->>'action_type')::INTEGER, 0),
                    COALESCE(event.data->'params', '{}'),
                    COALESCE((event.data->>'timeout_seconds')::INTEGER, 300),
                    event.occurred_at,
                    event.actor_id,
                    event.sequence_num
                );
            END IF;

        WHEN 'DefinitionRenamed' THEN
            UPDATE actions_projection
            SET name = event.data->>'name',
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'DefinitionDescriptionUpdated' THEN
            UPDATE actions_projection
            SET description = event.data->>'description',
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'DefinitionParamsUpdated' THEN
            UPDATE actions_projection
            SET params = COALESCE(event.data->'params', params),
                timeout_seconds = COALESCE((event.data->>'timeout_seconds')::INTEGER, timeout_seconds),
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'DefinitionDeleted' THEN
            UPDATE actions_projection
            SET is_deleted = TRUE,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

            -- Cascade: Update member counts for affected action sets
            UPDATE action_sets_projection
            SET member_count = member_count - 1
            WHERE id IN (
                SELECT set_id FROM action_set_members_projection WHERE action_id = event.stream_id
            );

            -- Cascade: Remove action from all action sets
            DELETE FROM action_set_members_projection WHERE action_id = event.stream_id;

        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- +goose StatementBegin
-- Update project_action_set_event to cascade delete to definition_members_projection
CREATE OR REPLACE FUNCTION project_action_set_event(event events) RETURNS void AS $$
BEGIN
    CASE event.event_type
        WHEN 'ActionSetCreated' THEN
            INSERT INTO action_sets_projection (
                id, name, description, created_at, created_by, projection_version
            ) VALUES (
                event.stream_id,
                event.data->>'name',
                COALESCE(event.data->>'description', ''),
                event.occurred_at,
                event.actor_id,
                event.sequence_num
            );

        WHEN 'ActionSetRenamed' THEN
            UPDATE action_sets_projection
            SET name = event.data->>'name',
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'ActionSetDescriptionUpdated' THEN
            UPDATE action_sets_projection
            SET description = COALESCE(event.data->>'description', ''),
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
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'ActionSetMemberRemoved' THEN
            DELETE FROM action_set_members_projection
            WHERE set_id = event.stream_id AND action_id = event.data->>'action_id';

            UPDATE action_sets_projection
            SET member_count = (SELECT COUNT(*) FROM action_set_members_projection WHERE set_id = event.stream_id),
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'ActionSetMemberReordered' THEN
            UPDATE action_set_members_projection
            SET sort_order = COALESCE((event.data->>'sort_order')::INTEGER, 0),
                projection_version = event.sequence_num
            WHERE set_id = event.stream_id AND action_id = event.data->>'action_id';

        WHEN 'ActionSetDeleted' THEN
            UPDATE action_sets_projection
            SET is_deleted = TRUE,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

            -- Delete members of this action set
            DELETE FROM action_set_members_projection WHERE set_id = event.stream_id;

            -- Cascade: Update member counts for affected definitions
            UPDATE definitions_projection
            SET member_count = member_count - 1
            WHERE id IN (
                SELECT definition_id FROM definition_members_projection WHERE action_set_id = event.stream_id
            );

            -- Cascade: Remove action set from all definitions
            DELETE FROM definition_members_projection WHERE action_set_id = event.stream_id;

        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd


-- +goose Down
-- Restore original functions without cascade deletes

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_action_event(event events) RETURNS void AS $$
BEGIN
    CASE event.event_type
        WHEN 'ActionCreated' THEN
            INSERT INTO actions_projection (
                id, name, description, action_type,
                params, timeout_seconds, created_at, created_by, projection_version
            ) VALUES (
                event.stream_id,
                event.data->>'name',
                event.data->>'description',
                COALESCE((event.data->>'action_type')::INTEGER, 0),
                COALESCE(event.data->'params', '{}'),
                COALESCE((event.data->>'timeout_seconds')::INTEGER, 300),
                event.occurred_at,
                event.actor_id,
                event.sequence_num
            );

        WHEN 'ActionRenamed' THEN
            UPDATE actions_projection
            SET name = event.data->>'name',
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'ActionDescriptionUpdated' THEN
            UPDATE actions_projection
            SET description = event.data->>'description',
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'ActionParamsUpdated' THEN
            UPDATE actions_projection
            SET params = COALESCE(event.data->'params', params),
                timeout_seconds = COALESCE((event.data->>'timeout_seconds')::INTEGER, timeout_seconds),
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'ActionDeleted' THEN
            UPDATE actions_projection
            SET is_deleted = TRUE,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        -- Legacy single-action definition events (backward compatibility)
        WHEN 'DefinitionCreated' THEN
            IF event.data ? 'action_type' THEN
                INSERT INTO actions_projection (
                    id, name, description, action_type,
                    params, timeout_seconds, created_at, created_by, projection_version
                ) VALUES (
                    event.stream_id,
                    event.data->>'name',
                    event.data->>'description',
                    COALESCE((event.data->>'action_type')::INTEGER, 0),
                    COALESCE(event.data->'params', '{}'),
                    COALESCE((event.data->>'timeout_seconds')::INTEGER, 300),
                    event.occurred_at,
                    event.actor_id,
                    event.sequence_num
                );
            END IF;

        WHEN 'DefinitionRenamed' THEN
            UPDATE actions_projection
            SET name = event.data->>'name',
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'DefinitionDescriptionUpdated' THEN
            UPDATE actions_projection
            SET description = event.data->>'description',
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'DefinitionParamsUpdated' THEN
            UPDATE actions_projection
            SET params = COALESCE(event.data->'params', params),
                timeout_seconds = COALESCE((event.data->>'timeout_seconds')::INTEGER, timeout_seconds),
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'DefinitionDeleted' THEN
            UPDATE actions_projection
            SET is_deleted = TRUE,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_action_set_event(event events) RETURNS void AS $$
BEGIN
    CASE event.event_type
        WHEN 'ActionSetCreated' THEN
            INSERT INTO action_sets_projection (
                id, name, description, created_at, created_by, projection_version
            ) VALUES (
                event.stream_id,
                event.data->>'name',
                COALESCE(event.data->>'description', ''),
                event.occurred_at,
                event.actor_id,
                event.sequence_num
            );

        WHEN 'ActionSetRenamed' THEN
            UPDATE action_sets_projection
            SET name = event.data->>'name',
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'ActionSetDescriptionUpdated' THEN
            UPDATE action_sets_projection
            SET description = COALESCE(event.data->>'description', ''),
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
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'ActionSetMemberRemoved' THEN
            DELETE FROM action_set_members_projection
            WHERE set_id = event.stream_id AND action_id = event.data->>'action_id';

            UPDATE action_sets_projection
            SET member_count = (SELECT COUNT(*) FROM action_set_members_projection WHERE set_id = event.stream_id),
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'ActionSetMemberReordered' THEN
            UPDATE action_set_members_projection
            SET sort_order = COALESCE((event.data->>'sort_order')::INTEGER, 0),
                projection_version = event.sequence_num
            WHERE set_id = event.stream_id AND action_id = event.data->>'action_id';

        WHEN 'ActionSetDeleted' THEN
            UPDATE action_sets_projection
            SET is_deleted = TRUE,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

            DELETE FROM action_set_members_projection WHERE set_id = event.stream_id;

        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
