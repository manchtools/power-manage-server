-- Add a `schedule` JSONB column to action_sets_projection and
-- definitions_projection. The schedule on a set or definition fires every
-- member action when triggered, overriding each member action's own
-- schedule. Member actions never fire on their own when assigned via a
-- set or definition — only via the container's schedule. This is what
-- makes ordering guarantees possible: when the container fires, every
-- one of its actions enters the queue together in declared order rather
-- than each firing independently and racing.
--
-- The default `{"interval_hours": 8}` mirrors the existing per-action
-- default cadence, so any pre-existing rows behave the same as before
-- once they're delivered through the new sync wire shape.
--
-- Two new event types are introduced:
--   - ActionSetScheduleUpdated  (data: {"schedule": <ActionSchedule JSON>})
--   - DefinitionScheduleUpdated (data: {"schedule": <ActionSchedule JSON>})
--
-- ActionSetCreated and DefinitionCreated also gain a `schedule` payload
-- field; absent payloads fall back to the column default for backward
-- compatibility with replays of older events.
--
-- See manchtools/power-manage-agent#45.

-- +goose Up

ALTER TABLE action_sets_projection
    ADD COLUMN schedule JSONB NOT NULL DEFAULT '{"interval_hours": 8}'::JSONB;

ALTER TABLE definitions_projection
    ADD COLUMN schedule JSONB NOT NULL DEFAULT '{"interval_hours": 8}'::JSONB;

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

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_definition_event(event events) RETURNS void AS $$
BEGIN
    CASE event.event_type
        WHEN 'DefinitionCreated' THEN
            IF NOT (event.data ? 'action_type') THEN
                INSERT INTO definitions_projection (
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

        WHEN 'DefinitionScheduleUpdated' THEN
            UPDATE definitions_projection
            SET schedule = COALESCE((event.data->'schedule')::JSONB, '{"interval_hours": 8}'::JSONB),
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

        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd


-- +goose Down

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

        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

ALTER TABLE definitions_projection DROP COLUMN schedule;
ALTER TABLE action_sets_projection DROP COLUMN schedule;
