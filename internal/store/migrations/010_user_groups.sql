-- +goose Up

-- User groups projection
CREATE TABLE user_groups_projection (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    member_count INT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
    projection_version BIGINT NOT NULL DEFAULT 0
);

CREATE UNIQUE INDEX idx_user_groups_name ON user_groups_projection(name) WHERE is_deleted = FALSE;

-- User group members projection
CREATE TABLE user_group_members_projection (
    group_id TEXT NOT NULL REFERENCES user_groups_projection(id),
    user_id TEXT NOT NULL REFERENCES users_projection(id),
    added_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    added_by TEXT NOT NULL DEFAULT '',
    projection_version BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (group_id, user_id)
);

CREATE INDEX idx_user_group_members_user ON user_group_members_projection(user_id);

-- User group roles projection
CREATE TABLE user_group_roles_projection (
    group_id TEXT NOT NULL REFERENCES user_groups_projection(id),
    role_id TEXT NOT NULL REFERENCES roles_projection(id),
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    assigned_by TEXT NOT NULL DEFAULT '',
    projection_version BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (group_id, role_id)
);

CREATE INDEX idx_user_group_roles_role ON user_group_roles_projection(role_id);

-- Projector function for user_group events
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_user_group_event(event events) RETURNS void AS $$
BEGIN
    CASE event.event_type
        WHEN 'UserGroupCreated' THEN
            INSERT INTO user_groups_projection (
                id, name, description, member_count,
                created_at, created_by, updated_at, projection_version
            ) VALUES (
                event.stream_id,
                event.data->>'name',
                COALESCE(event.data->>'description', ''),
                0,
                event.occurred_at,
                event.actor_id,
                event.occurred_at,
                event.sequence_num
            );

        WHEN 'UserGroupUpdated' THEN
            UPDATE user_groups_projection
            SET name = event.data->>'name',
                description = COALESCE(event.data->>'description', ''),
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'UserGroupDeleted' THEN
            UPDATE user_groups_projection
            SET is_deleted = TRUE,
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

            -- Clean up members and roles
            DELETE FROM user_group_members_projection WHERE group_id = event.stream_id;
            DELETE FROM user_group_roles_projection WHERE group_id = event.stream_id;

        WHEN 'UserGroupMemberAdded' THEN
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

        WHEN 'UserGroupMemberRemoved' THEN
            DELETE FROM user_group_members_projection
            WHERE group_id = event.data->>'group_id'
              AND user_id = event.data->>'user_id';

            UPDATE user_groups_projection
            SET member_count = GREATEST(member_count - 1, 0),
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.data->>'group_id';

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

        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- Add user_group stream type to the master projector
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_event() RETURNS trigger AS $$
BEGIN
    CASE NEW.stream_type
        WHEN 'user' THEN
            BEGIN
                PERFORM project_user_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        WHEN 'token' THEN
            BEGIN
                PERFORM project_token_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        WHEN 'device' THEN
            BEGIN
                PERFORM project_device_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        WHEN 'action' THEN
            BEGIN
                PERFORM project_action_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        WHEN 'definition' THEN
            BEGIN
                PERFORM project_action_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, 'definition->action', SQLERRM);
            END;

            BEGIN
                PERFORM project_definition_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, 'definition->definition', SQLERRM);
            END;

        WHEN 'action_set' THEN
            BEGIN
                PERFORM project_action_set_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        WHEN 'device_group' THEN
            BEGIN
                PERFORM project_device_group_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        WHEN 'assignment' THEN
            BEGIN
                PERFORM project_assignment_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        WHEN 'execution' THEN
            BEGIN
                PERFORM project_execution_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        WHEN 'user_selection' THEN
            BEGIN
                PERFORM project_user_selection_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        WHEN 'role' THEN
            BEGIN
                PERFORM project_role_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        WHEN 'user_role' THEN
            BEGIN
                PERFORM project_user_role_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        WHEN 'totp' THEN
            BEGIN
                PERFORM project_totp_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        WHEN 'user_group' THEN
            BEGIN
                PERFORM project_user_group_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        ELSE
            NULL;
    END CASE;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- Rebuild function for user groups projection
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION rebuild_user_groups_projection() RETURNS void AS $$
DECLARE
    event_record events;
BEGIN
    TRUNCATE user_group_roles_projection;
    TRUNCATE user_group_members_projection;
    TRUNCATE user_groups_projection CASCADE;
    FOR event_record IN SELECT * FROM events WHERE stream_type = 'user_group' ORDER BY sequence_num LOOP
        PERFORM project_user_group_event(event_record);
    END LOOP;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- +goose Down

DROP FUNCTION IF EXISTS rebuild_user_groups_projection;
DROP FUNCTION IF EXISTS project_user_group_event;
DROP TABLE IF EXISTS user_group_roles_projection;
DROP TABLE IF EXISTS user_group_members_projection;
DROP TABLE IF EXISTS user_groups_projection;
