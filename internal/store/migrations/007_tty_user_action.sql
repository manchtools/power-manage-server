-- +goose Up

-- Add system_tty_action_id to users_projection for tracking the
-- auto-created pm-tty-* User action per Power Manage user.
ALTER TABLE users_projection
    ADD COLUMN IF NOT EXISTS system_tty_action_id TEXT NOT NULL DEFAULT '';

-- Extend the UserSystemActionLinked handler in the user projector to
-- also handle the system_tty_action_id field. The full function body
-- is reproduced because CREATE OR REPLACE replaces the entire body.
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
            DELETE FROM identity_links_projection WHERE user_id = event.stream_id;

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
                system_tty_action_id = CASE
                    WHEN event.data->>'field' = 'system_tty_action_id' THEN COALESCE(event.data->>'action_id', '')
                    ELSE system_tty_action_id
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

-- +goose Down
ALTER TABLE users_projection DROP COLUMN IF EXISTS system_tty_action_id;
-- The down migration does not restore the old function body; running
-- all downs in reverse order (006 → 005 → ... → 002) handles that.
