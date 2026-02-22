-- +goose Up

-- Update user group projector to clean up SCIM group mappings when a group is deleted.
-- Without this, deleting a user group in Power Manage leaves orphaned SCIM mappings
-- that cause 500 errors when the SCIM provider syncs.
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

-- +goose Down

-- Revert to original without SCIM cleanup
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
