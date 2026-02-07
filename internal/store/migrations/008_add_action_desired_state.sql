-- +goose Up
-- Add desired_state column to actions_projection
ALTER TABLE actions_projection ADD COLUMN IF NOT EXISTS desired_state INTEGER NOT NULL DEFAULT 0;

-- +goose StatementBegin
-- Update projection function to handle desired_state field
CREATE OR REPLACE FUNCTION project_action_event(event events) RETURNS void AS $$
BEGIN
    CASE event.event_type
        WHEN 'ActionCreated' THEN
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

        -- Legacy single-action definition events (backward compatibility)
        WHEN 'DefinitionCreated' THEN
            -- Only handle old-style definitions that have action_type
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

        WHEN 'DefinitionParamsUpdated' THEN
            UPDATE actions_projection
            SET params = COALESCE(event.data->'params', params),
                timeout_seconds = COALESCE((event.data->>'timeout_seconds')::INTEGER, timeout_seconds),
                desired_state = COALESCE((event.data->>'desired_state')::INTEGER, desired_state),
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

-- +goose Down
-- +goose StatementBegin
-- Restore original function without desired_state
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

        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

ALTER TABLE actions_projection DROP COLUMN IF EXISTS desired_state;
