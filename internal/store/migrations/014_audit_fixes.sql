-- +goose Up

-- 1. Fix email UNIQUE constraint to allow re-provisioning deleted users.
-- The old UNIQUE constraint on email prevented creating a new user with the
-- same email as a soft-deleted user. A partial unique index only enforces
-- uniqueness among non-deleted users.
ALTER TABLE users_projection DROP CONSTRAINT users_projection_email_key;
CREATE UNIQUE INDEX idx_users_email_active ON users_projection(email) WHERE is_deleted = FALSE;

-- 2. Fix UserGroupUpdated description wipe.
-- The projector previously used COALESCE(event.data->>'description', '') which
-- wiped the description when SCIM updates only provided a name. Changed to
-- COALESCE(event.data->>'description', description) to preserve existing value.
-- Also carried forward the SCIM cleanup from migration 013.
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
                description = COALESCE(event.data->>'description', description),
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'UserGroupDeleted' THEN
            -- Clean up SCIM group mappings that reference this group
            DELETE FROM scim_group_mapping_projection WHERE user_group_id = event.stream_id;

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

-- 3. Fix UserDeleted to clean up identity links.
-- Without this, deleted users' identity links remain in the database, causing
-- confusing errors when the same user tries to log in via SSO.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_user_event(event events) RETURNS void AS $$
BEGIN
    CASE event.event_type
        WHEN 'UserCreated' THEN
            INSERT INTO users_projection (
                id, email, password_hash, role, created_at, updated_at, projection_version, session_version, has_password
            ) VALUES (
                event.stream_id,
                event.data->>'email',
                COALESCE(event.data->>'password_hash', ''),
                COALESCE(event.data->>'role', 'user'),
                event.occurred_at,
                event.occurred_at,
                event.sequence_num,
                0,
                COALESCE(NULLIF(event.data->>'password_hash', ''), NULL) IS NOT NULL
            );

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
            -- Clean up identity links so user can be re-provisioned via SSO/SCIM
            DELETE FROM identity_links_projection WHERE user_id = event.stream_id;

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

-- +goose Down

-- Revert email constraint
DROP INDEX IF EXISTS idx_users_email_active;
ALTER TABLE users_projection ADD CONSTRAINT users_projection_email_key UNIQUE (email);

-- Revert project_user_group_event (restore from migration 013)
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
            DELETE FROM scim_group_mapping_projection WHERE user_group_id = event.stream_id;

            UPDATE user_groups_projection
            SET is_deleted = TRUE,
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

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

-- Revert project_user_event (restore from migration 011 — without identity link cleanup)
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_user_event(event events) RETURNS void AS $$
BEGIN
    CASE event.event_type
        WHEN 'UserCreated' THEN
            INSERT INTO users_projection (
                id, email, password_hash, role, created_at, updated_at, projection_version, session_version, has_password
            ) VALUES (
                event.stream_id,
                event.data->>'email',
                COALESCE(event.data->>'password_hash', ''),
                COALESCE(event.data->>'role', 'user'),
                event.occurred_at,
                event.occurred_at,
                event.sequence_num,
                0,
                COALESCE(NULLIF(event.data->>'password_hash', ''), NULL) IS NOT NULL
            );

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
