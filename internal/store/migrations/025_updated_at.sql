-- +goose Up

-- Add updated_at column to actions, action sets, and definitions projections
ALTER TABLE actions_projection ADD COLUMN updated_at TIMESTAMPTZ;
ALTER TABLE action_sets_projection ADD COLUMN updated_at TIMESTAMPTZ;
ALTER TABLE definitions_projection ADD COLUMN updated_at TIMESTAMPTZ;

-- Backfill from the latest event for each entity
UPDATE actions_projection SET updated_at = COALESCE(
    (SELECT MAX(occurred_at) FROM events WHERE stream_id = actions_projection.id),
    created_at
);
UPDATE action_sets_projection SET updated_at = COALESCE(
    (SELECT MAX(occurred_at) FROM events WHERE stream_id = action_sets_projection.id),
    created_at
);
UPDATE definitions_projection SET updated_at = COALESCE(
    (SELECT MAX(occurred_at) FROM events WHERE stream_id = definitions_projection.id),
    created_at
);

-- Update action event projector to set updated_at
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_action_event(event events) RETURNS void AS $$
BEGIN
    CASE event.event_type
        WHEN 'ActionCreated' THEN
            INSERT INTO actions_projection (
                id, name, description, action_type, desired_state,
                params, timeout_seconds, created_at, updated_at, created_by, projection_version,
                is_system
            ) VALUES (
                event.stream_id,
                event.data->>'name',
                event.data->>'description',
                COALESCE((event.data->>'action_type')::INTEGER, 0),
                COALESCE((event.data->>'desired_state')::INTEGER, 0),
                COALESCE(event.data->'params', '{}'),
                COALESCE((event.data->>'timeout_seconds')::INTEGER, 300),
                event.occurred_at,
                event.occurred_at,
                event.actor_id,
                event.sequence_num,
                COALESCE((event.data->>'is_system')::BOOLEAN, FALSE)
            );

        WHEN 'ActionRenamed' THEN
            UPDATE actions_projection
            SET name = event.data->>'name',
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'ActionDescriptionUpdated' THEN
            UPDATE actions_projection
            SET description = event.data->>'description',
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'ActionParamsUpdated' THEN
            UPDATE actions_projection
            SET params = COALESCE(event.data->'params', params),
                timeout_seconds = COALESCE((event.data->>'timeout_seconds')::INTEGER, timeout_seconds),
                desired_state = COALESCE((event.data->>'desired_state')::INTEGER, desired_state),
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'ActionDeleted' THEN
            UPDATE actions_projection
            SET is_deleted = TRUE,
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

            UPDATE action_sets_projection
            SET member_count = member_count - 1
            WHERE id IN (
                SELECT set_id FROM action_set_members_projection WHERE action_id = event.stream_id
            );

            DELETE FROM action_set_members_projection WHERE action_id = event.stream_id;

        WHEN 'DefinitionCreated' THEN
            IF event.data ? 'action_type' THEN
                INSERT INTO actions_projection (
                    id, name, description, action_type, desired_state,
                    params, timeout_seconds, created_at, updated_at, created_by, projection_version
                ) VALUES (
                    event.stream_id,
                    event.data->>'name',
                    event.data->>'description',
                    COALESCE((event.data->>'action_type')::INTEGER, 0),
                    COALESCE((event.data->>'desired_state')::INTEGER, 0),
                    COALESCE(event.data->'params', '{}'),
                    COALESCE((event.data->>'timeout_seconds')::INTEGER, 300),
                    event.occurred_at,
                    event.occurred_at,
                    event.actor_id,
                    event.sequence_num
                );
            END IF;

        WHEN 'DefinitionRenamed' THEN
            UPDATE actions_projection
            SET name = event.data->>'name',
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'DefinitionDescriptionUpdated' THEN
            UPDATE actions_projection
            SET description = event.data->>'description',
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'DefinitionDeleted' THEN
            UPDATE actions_projection
            SET is_deleted = TRUE,
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- Update action set event projector to set updated_at
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_action_set_event(event events) RETURNS void AS $$
BEGIN
    CASE event.event_type
        WHEN 'ActionSetCreated' THEN
            INSERT INTO action_sets_projection (
                id, name, description, created_at, updated_at, created_by, projection_version
            ) VALUES (
                event.stream_id,
                event.data->>'name',
                COALESCE(event.data->>'description', ''),
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

-- Update definition event projector to set updated_at
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_definition_event(event events) RETURNS void AS $$
BEGIN
    CASE event.event_type
        WHEN 'DefinitionCreated' THEN
            IF NOT (event.data ? 'action_type') THEN
                INSERT INTO definitions_projection (
                    id, name, description, created_at, updated_at, created_by, projection_version
                ) VALUES (
                    event.stream_id,
                    event.data->>'name',
                    COALESCE(event.data->>'description', ''),
                    event.occurred_at,
                    event.occurred_at,
                    event.actor_id,
                    event.sequence_num
                );
            END IF;

        WHEN 'DefinitionRenamed' THEN
            UPDATE definitions_projection
            SET name = event.data->>'name',
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'DefinitionDescriptionUpdated' THEN
            UPDATE definitions_projection
            SET description = COALESCE(event.data->>'description', ''),
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'DefinitionMemberAdded' THEN
            INSERT INTO definition_members_projection (
                definition_id, action_set_id, sort_order, added_at, projection_version
            ) VALUES (
                event.stream_id,
                event.data->>'action_set_id',
                COALESCE((event.data->>'sort_order')::INTEGER, 0),
                event.occurred_at,
                event.sequence_num
            ) ON CONFLICT (definition_id, action_set_id) DO NOTHING;

            UPDATE definitions_projection
            SET member_count = (SELECT COUNT(*) FROM definition_members_projection WHERE definition_id = event.stream_id),
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'DefinitionMemberRemoved' THEN
            DELETE FROM definition_members_projection
            WHERE definition_id = event.stream_id AND action_set_id = event.data->>'action_set_id';

            UPDATE definitions_projection
            SET member_count = (SELECT COUNT(*) FROM definition_members_projection WHERE definition_id = event.stream_id),
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'DefinitionMemberReordered' THEN
            UPDATE definition_members_projection
            SET sort_order = COALESCE((event.data->>'sort_order')::INTEGER, 0),
                projection_version = event.sequence_num
            WHERE definition_id = event.stream_id AND action_set_id = event.data->>'action_set_id';

            UPDATE definitions_projection
            SET updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'DefinitionDeleted' THEN
            UPDATE definitions_projection
            SET is_deleted = TRUE,
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

            DELETE FROM definition_members_projection WHERE definition_id = event.stream_id;

        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- +goose Down

-- Restore action event projector without updated_at (from migration 019)
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_action_event(event events) RETURNS void AS $$
BEGIN
    CASE event.event_type
        WHEN 'ActionCreated' THEN
            INSERT INTO actions_projection (
                id, name, description, action_type, desired_state,
                params, timeout_seconds, created_at, created_by, projection_version,
                is_system
            ) VALUES (
                event.stream_id,
                event.data->>'name',
                event.data->>'description',
                COALESCE((event.data->>'action_type')::INTEGER, 0),
                COALESCE((event.data->>'desired_state')::INTEGER, 0),
                COALESCE(event.data->'params', '{}'),
                COALESCE((event.data->>'timeout_seconds')::INTEGER, 300),
                event.occurred_at,
                event.actor_id,
                event.sequence_num,
                COALESCE((event.data->>'is_system')::BOOLEAN, FALSE)
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
                desired_state = COALESCE((event.data->>'desired_state')::INTEGER, desired_state),
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'ActionDeleted' THEN
            UPDATE actions_projection
            SET is_deleted = TRUE,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

            UPDATE action_sets_projection
            SET member_count = member_count - 1
            WHERE id IN (
                SELECT set_id FROM action_set_members_projection WHERE action_id = event.stream_id
            );

            DELETE FROM action_set_members_projection WHERE action_id = event.stream_id;

        WHEN 'DefinitionCreated' THEN
            IF event.data ? 'action_type' THEN
                INSERT INTO actions_projection (
                    id, name, description, action_type, desired_state,
                    params, timeout_seconds, created_at, created_by, projection_version
                ) VALUES (
                    event.stream_id,
                    event.data->>'name',
                    event.data->>'description',
                    COALESCE((event.data->>'action_type')::INTEGER, 0),
                    COALESCE((event.data->>'desired_state')::INTEGER, 0),
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

-- Restore action set event projector without updated_at (from migration 001)
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

-- Restore definition event projector without updated_at (from migration 001)
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_definition_event(event events) RETURNS void AS $$
BEGIN
    CASE event.event_type
        WHEN 'DefinitionCreated' THEN
            IF NOT (event.data ? 'action_type') THEN
                INSERT INTO definitions_projection (
                    id, name, description, created_at, created_by, projection_version
                ) VALUES (
                    event.stream_id,
                    event.data->>'name',
                    COALESCE(event.data->>'description', ''),
                    event.occurred_at,
                    event.actor_id,
                    event.sequence_num
                );
            END IF;

        WHEN 'DefinitionRenamed' THEN
            UPDATE definitions_projection
            SET name = event.data->>'name',
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'DefinitionDescriptionUpdated' THEN
            UPDATE definitions_projection
            SET description = COALESCE(event.data->>'description', ''),
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'DefinitionMemberAdded' THEN
            INSERT INTO definition_members_projection (
                definition_id, action_set_id, sort_order, added_at, projection_version
            ) VALUES (
                event.stream_id,
                event.data->>'action_set_id',
                COALESCE((event.data->>'sort_order')::INTEGER, 0),
                event.occurred_at,
                event.sequence_num
            ) ON CONFLICT (definition_id, action_set_id) DO NOTHING;

            UPDATE definitions_projection
            SET member_count = (SELECT COUNT(*) FROM definition_members_projection WHERE definition_id = event.stream_id),
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'DefinitionMemberRemoved' THEN
            DELETE FROM definition_members_projection
            WHERE definition_id = event.stream_id AND action_set_id = event.data->>'action_set_id';

            UPDATE definitions_projection
            SET member_count = (SELECT COUNT(*) FROM definition_members_projection WHERE definition_id = event.stream_id),
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'DefinitionMemberReordered' THEN
            UPDATE definition_members_projection
            SET sort_order = COALESCE((event.data->>'sort_order')::INTEGER, 0),
                projection_version = event.sequence_num
            WHERE definition_id = event.stream_id AND action_set_id = event.data->>'action_set_id';

        WHEN 'DefinitionDeleted' THEN
            UPDATE definitions_projection
            SET is_deleted = TRUE,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

            DELETE FROM definition_members_projection WHERE definition_id = event.stream_id;

        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

ALTER TABLE actions_projection DROP COLUMN IF EXISTS updated_at;
ALTER TABLE action_sets_projection DROP COLUMN IF EXISTS updated_at;
ALTER TABLE definitions_projection DROP COLUMN IF EXISTS updated_at;
