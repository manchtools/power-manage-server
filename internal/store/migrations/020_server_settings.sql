-- +goose Up

-- Global server settings (single-row table)
CREATE TABLE server_settings_projection (
    id TEXT PRIMARY KEY DEFAULT 'global',
    user_provisioning_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    ssh_access_for_all BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    projection_version BIGINT NOT NULL DEFAULT 0
);
INSERT INTO server_settings_projection (id) VALUES ('global');

-- Per-user provisioning override
ALTER TABLE users_projection ADD COLUMN user_provisioning_enabled BOOLEAN NOT NULL DEFAULT FALSE;

-- Projector for server_settings events
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_server_settings_event(event events) RETURNS void AS $$
BEGIN
    CASE event.event_type
        WHEN 'ServerSettingUpdated' THEN
            UPDATE server_settings_projection
            SET user_provisioning_enabled = COALESCE((event.data->>'user_provisioning_enabled')::BOOLEAN, user_provisioning_enabled),
                ssh_access_for_all = COALESCE((event.data->>'ssh_access_for_all')::BOOLEAN, ssh_access_for_all),
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = 'global';
        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- Update user event projector to handle UserProvisioningSettingsUpdated
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

        WHEN 'UserProvisioningSettingsUpdated' THEN
            UPDATE users_projection
            SET user_provisioning_enabled = COALESCE((event.data->>'user_provisioning_enabled')::BOOLEAN, user_provisioning_enabled),
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- Update project_event() dispatcher to route server_settings events
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

        WHEN 'identity_provider' THEN
            BEGIN
                PERFORM project_identity_provider_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        WHEN 'scim_group_mapping' THEN
            BEGIN
                PERFORM project_scim_group_mapping_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        WHEN 'compliance' THEN
            BEGIN
                PERFORM project_compliance_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        WHEN 'compliance_policy' THEN
            BEGIN
                PERFORM project_compliance_policy_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        WHEN 'server_settings' THEN
            BEGIN
                PERFORM project_server_settings_event(NEW);
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

-- +goose Down

-- Restore project_event() without server_settings
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

        WHEN 'identity_provider' THEN
            BEGIN
                PERFORM project_identity_provider_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        WHEN 'scim_group_mapping' THEN
            BEGIN
                PERFORM project_scim_group_mapping_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        WHEN 'compliance' THEN
            BEGIN
                PERFORM project_compliance_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        WHEN 'compliance_policy' THEN
            BEGIN
                PERFORM project_compliance_policy_event(NEW);
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

-- Restore user event projector from migration 019
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

DROP FUNCTION IF EXISTS project_server_settings_event(events);
ALTER TABLE users_projection DROP COLUMN IF EXISTS user_provisioning_enabled;
DROP TABLE IF EXISTS server_settings_projection;
