-- +goose Up

-- Linux identity columns for users
ALTER TABLE users_projection ADD COLUMN linux_username TEXT NOT NULL DEFAULT '';
ALTER TABLE users_projection ADD COLUMN linux_uid INTEGER NOT NULL DEFAULT 0;

-- SSH access settings per user
ALTER TABLE users_projection ADD COLUMN ssh_public_keys JSONB NOT NULL DEFAULT '[]';
ALTER TABLE users_projection ADD COLUMN ssh_access_enabled BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users_projection ADD COLUMN ssh_allow_pubkey BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE users_projection ADD COLUMN ssh_allow_password BOOLEAN NOT NULL DEFAULT FALSE;

-- Track system-managed action IDs per user
ALTER TABLE users_projection ADD COLUMN system_user_action_id TEXT NOT NULL DEFAULT '';
ALTER TABLE users_projection ADD COLUMN system_ssh_action_id TEXT NOT NULL DEFAULT '';

-- System flag on actions
ALTER TABLE actions_projection ADD COLUMN is_system BOOLEAN NOT NULL DEFAULT FALSE;

-- UID sequence (start at 10000 to avoid clashing with local users)
CREATE SEQUENCE linux_uid_seq START WITH 10000;

-- Backfill existing users with linux_uid and linux_username
-- +goose StatementBegin
DO $$
DECLARE
    u RECORD;
    raw_username TEXT;
    clean_username TEXT;
BEGIN
    FOR u IN SELECT id, email, preferred_username FROM users_projection WHERE is_deleted = FALSE AND linux_uid = 0 LOOP
        -- Derive username: preferred_username > email prefix > email
        IF u.preferred_username IS NOT NULL AND u.preferred_username != '' THEN
            raw_username := u.preferred_username;
        ELSIF u.email LIKE '%@%' THEN
            raw_username := SPLIT_PART(u.email, '@', 1);
        ELSE
            raw_username := u.email;
        END IF;

        -- Sanitize: lowercase, replace invalid chars, truncate
        clean_username := LOWER(raw_username);
        clean_username := regexp_replace(clean_username, '[^a-z0-9_.\-]', '_', 'g');
        IF LENGTH(clean_username) > 32 THEN
            clean_username := LEFT(clean_username, 32);
        END IF;
        IF clean_username = '' THEN
            clean_username := 'user_' || LEFT(u.id, 8);
        END IF;

        UPDATE users_projection
        SET linux_uid = nextval('linux_uid_seq'),
            linux_username = clean_username
        WHERE id = u.id;
    END LOOP;
END;
$$;
-- +goose StatementEnd

-- Update user event projector to handle new event types
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_user_event(event events) RETURNS void AS $$
BEGIN
    CASE event.event_type
        WHEN 'UserCreated' THEN
            INSERT INTO users_projection (
                id, email, password_hash, role, created_at, updated_at, projection_version, session_version, has_password,
                display_name, given_name, family_name, preferred_username, picture, locale,
                linux_username, linux_uid
            ) VALUES (
                event.stream_id,
                event.data->>'email',
                COALESCE(event.data->>'password_hash', ''),
                COALESCE(event.data->>'role', 'user'),
                event.occurred_at,
                event.occurred_at,
                event.sequence_num,
                0,
                COALESCE(NULLIF(event.data->>'password_hash', ''), NULL) IS NOT NULL,
                COALESCE(event.data->>'display_name', ''),
                COALESCE(event.data->>'given_name', ''),
                COALESCE(event.data->>'family_name', ''),
                COALESCE(event.data->>'preferred_username', ''),
                COALESCE(event.data->>'picture', ''),
                COALESCE(event.data->>'locale', ''),
                COALESCE(event.data->>'linux_username', ''),
                COALESCE((event.data->>'linux_uid')::INTEGER, 0)
            );

        WHEN 'UserProfileUpdated' THEN
            UPDATE users_projection
            SET display_name = COALESCE(event.data->>'display_name', ''),
                given_name = COALESCE(event.data->>'given_name', ''),
                family_name = COALESCE(event.data->>'family_name', ''),
                preferred_username = COALESCE(event.data->>'preferred_username', ''),
                picture = COALESCE(event.data->>'picture', ''),
                locale = COALESCE(event.data->>'locale', ''),
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'UserEmailChanged' THEN
            UPDATE users_projection
            SET email = event.data->>'email',
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'UserPasswordChanged' THEN
            UPDATE users_projection
            SET password_hash = event.data->>'password_hash',
                has_password = TRUE,
                session_version = session_version + 1,
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'UserRoleChanged' THEN
            UPDATE users_projection
            SET role = event.data->>'role',
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'UserSessionInvalidated' THEN
            UPDATE users_projection
            SET session_version = session_version + 1,
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'UserDisabled' THEN
            UPDATE users_projection
            SET disabled = TRUE,
                session_version = session_version + 1,
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'UserEnabled' THEN
            UPDATE users_projection
            SET disabled = FALSE,
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'UserLoggedIn' THEN
            UPDATE users_projection
            SET last_login_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'UserDeleted' THEN
            UPDATE users_projection
            SET is_deleted = TRUE,
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'UserSshKeyAdded' THEN
            UPDATE users_projection
            SET ssh_public_keys = ssh_public_keys || jsonb_build_array(
                jsonb_build_object(
                    'id', event.data->>'key_id',
                    'public_key', event.data->>'public_key',
                    'comment', event.data->>'comment',
                    'added_at', event.occurred_at
                )
            ),
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'UserSshKeyRemoved' THEN
            UPDATE users_projection
            SET ssh_public_keys = (
                SELECT COALESCE(jsonb_agg(elem), '[]'::jsonb)
                FROM jsonb_array_elements(ssh_public_keys) AS elem
                WHERE elem->>'id' != event.data->>'key_id'
            ),
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'UserSshSettingsUpdated' THEN
            UPDATE users_projection
            SET ssh_access_enabled = COALESCE((event.data->>'ssh_access_enabled')::BOOLEAN, ssh_access_enabled),
                ssh_allow_pubkey = COALESCE((event.data->>'ssh_allow_pubkey')::BOOLEAN, ssh_allow_pubkey),
                ssh_allow_password = COALESCE((event.data->>'ssh_allow_password')::BOOLEAN, ssh_allow_password),
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'UserLinuxUsernameChanged' THEN
            UPDATE users_projection
            SET linux_username = event.data->>'linux_username',
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'UserSystemActionLinked' THEN
            UPDATE users_projection
            SET system_user_action_id = CASE
                    WHEN event.data->>'field' = 'system_user_action_id' THEN COALESCE(event.data->>'action_id', '')
                    ELSE system_user_action_id
                END,
                system_ssh_action_id = CASE
                    WHEN event.data->>'field' = 'system_ssh_action_id' THEN COALESCE(event.data->>'action_id', '')
                    ELSE system_ssh_action_id
                END,
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- Update action event projector to handle is_system flag
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

-- +goose Down

-- Restore action event projector without is_system
-- +goose StatementBegin
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

-- Restore user event projector from migration 016
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_user_event(event events) RETURNS void AS $$
BEGIN
    CASE event.event_type
        WHEN 'UserCreated' THEN
            INSERT INTO users_projection (
                id, email, password_hash, role, created_at, updated_at, projection_version, session_version, has_password,
                display_name, given_name, family_name, preferred_username, picture, locale
            ) VALUES (
                event.stream_id,
                event.data->>'email',
                COALESCE(event.data->>'password_hash', ''),
                COALESCE(event.data->>'role', 'user'),
                event.occurred_at,
                event.occurred_at,
                event.sequence_num,
                0,
                COALESCE(NULLIF(event.data->>'password_hash', ''), NULL) IS NOT NULL,
                COALESCE(event.data->>'display_name', ''),
                COALESCE(event.data->>'given_name', ''),
                COALESCE(event.data->>'family_name', ''),
                COALESCE(event.data->>'preferred_username', ''),
                COALESCE(event.data->>'picture', ''),
                COALESCE(event.data->>'locale', '')
            );
        WHEN 'UserProfileUpdated' THEN
            UPDATE users_projection
            SET display_name = COALESCE(event.data->>'display_name', ''),
                given_name = COALESCE(event.data->>'given_name', ''),
                family_name = COALESCE(event.data->>'family_name', ''),
                preferred_username = COALESCE(event.data->>'preferred_username', ''),
                picture = COALESCE(event.data->>'picture', ''),
                locale = COALESCE(event.data->>'locale', ''),
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;
        WHEN 'UserEmailChanged' THEN
            UPDATE users_projection
            SET email = event.data->>'email',
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;
        WHEN 'UserPasswordChanged' THEN
            UPDATE users_projection
            SET password_hash = event.data->>'password_hash',
                has_password = TRUE,
                session_version = session_version + 1,
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;
        WHEN 'UserRoleChanged' THEN
            UPDATE users_projection
            SET role = event.data->>'role',
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;
        WHEN 'UserSessionInvalidated' THEN
            UPDATE users_projection
            SET session_version = session_version + 1,
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;
        WHEN 'UserDisabled' THEN
            UPDATE users_projection
            SET disabled = TRUE,
                session_version = session_version + 1,
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;
        WHEN 'UserEnabled' THEN
            UPDATE users_projection
            SET disabled = FALSE,
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;
        WHEN 'UserLoggedIn' THEN
            UPDATE users_projection
            SET last_login_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;
        WHEN 'UserDeleted' THEN
            UPDATE users_projection
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

DROP SEQUENCE IF EXISTS linux_uid_seq;
ALTER TABLE actions_projection DROP COLUMN IF EXISTS is_system;
ALTER TABLE users_projection DROP COLUMN IF EXISTS system_ssh_action_id;
ALTER TABLE users_projection DROP COLUMN IF EXISTS system_user_action_id;
ALTER TABLE users_projection DROP COLUMN IF EXISTS ssh_allow_password;
ALTER TABLE users_projection DROP COLUMN IF EXISTS ssh_allow_pubkey;
ALTER TABLE users_projection DROP COLUMN IF EXISTS ssh_access_enabled;
ALTER TABLE users_projection DROP COLUMN IF EXISTS ssh_public_keys;
ALTER TABLE users_projection DROP COLUMN IF EXISTS linux_uid;
ALTER TABLE users_projection DROP COLUMN IF EXISTS linux_username;
