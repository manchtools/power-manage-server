-- +goose Up

-- ============================================================================
-- Part 3: Extended Projector Functions (FINAL versions)
-- ============================================================================

-- 1. project_role_event (from 007_rbac.sql)
-- Handles: RoleCreated, RoleUpdated, RoleDeleted
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_role_event(event events) RETURNS void AS $$
BEGIN
    CASE event.event_type
        WHEN 'RoleCreated' THEN
            INSERT INTO roles_projection (
                id, name, description, permissions, is_system,
                created_at, created_by, projection_version
            ) VALUES (
                event.stream_id,
                event.data->>'name',
                COALESCE(event.data->>'description', ''),
                COALESCE(
                    ARRAY(SELECT jsonb_array_elements_text(event.data->'permissions')),
                    '{}'::TEXT[]
                ),
                COALESCE((event.data->>'is_system')::BOOLEAN, FALSE),
                event.occurred_at,
                event.actor_id,
                event.sequence_num
            );

        WHEN 'RoleUpdated' THEN
            UPDATE roles_projection
            SET name = COALESCE(NULLIF(event.data->>'name', ''), name),
                description = COALESCE(event.data->>'description', description),
                permissions = COALESCE(
                    ARRAY(SELECT jsonb_array_elements_text(event.data->'permissions')),
                    permissions
                ),
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'RoleDeleted' THEN
            UPDATE roles_projection
            SET is_deleted = TRUE,
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

            -- Remove all user-role assignments for this role
            DELETE FROM user_roles_projection WHERE role_id = event.stream_id;

        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- 2. project_user_role_event (from 007_rbac.sql)
-- Handles: UserRoleAssigned, UserRoleRevoked
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_user_role_event(event events) RETURNS void AS $$
BEGIN
    CASE event.event_type
        WHEN 'UserRoleAssigned' THEN
            INSERT INTO user_roles_projection (
                user_id, role_id, assigned_at, assigned_by, projection_version
            ) VALUES (
                event.data->>'user_id',
                event.data->>'role_id',
                event.occurred_at,
                event.actor_id,
                event.sequence_num
            ) ON CONFLICT (user_id, role_id) DO NOTHING;

        WHEN 'UserRoleRevoked' THEN
            DELETE FROM user_roles_projection
            WHERE user_id = event.data->>'user_id'
              AND role_id = event.data->>'role_id';

        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- 3. project_totp_event (from 009_totp.sql)
-- Handles: TOTPSetupInitiated, TOTPVerified, TOTPDisabled, TOTPBackupCodeUsed, TOTPBackupCodesRegenerated
-- Also updates users_projection.totp_enabled
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_totp_event(event events) RETURNS void AS $$
BEGIN
    CASE event.event_type
        WHEN 'TOTPSetupInitiated' THEN
            INSERT INTO totp_projection (
                user_id, secret_encrypted, verified, enabled,
                backup_codes_hash, backup_codes_used,
                created_at, updated_at, projection_version
            ) VALUES (
                event.stream_id,
                event.data->>'secret_encrypted',
                FALSE,
                FALSE,
                ARRAY(SELECT jsonb_array_elements_text(event.data->'backup_codes_hash')),
                ARRAY(SELECT FALSE FROM jsonb_array_elements_text(event.data->'backup_codes_hash')),
                event.occurred_at,
                event.occurred_at,
                event.sequence_num
            )
            ON CONFLICT (user_id) DO UPDATE SET
                secret_encrypted = EXCLUDED.secret_encrypted,
                verified = FALSE,
                enabled = FALSE,
                backup_codes_hash = EXCLUDED.backup_codes_hash,
                backup_codes_used = EXCLUDED.backup_codes_used,
                updated_at = EXCLUDED.updated_at,
                projection_version = EXCLUDED.projection_version;

        WHEN 'TOTPVerified' THEN
            UPDATE totp_projection
            SET verified = TRUE,
                enabled = TRUE,
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE user_id = event.stream_id;

            UPDATE users_projection
            SET totp_enabled = TRUE,
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'TOTPDisabled' THEN
            DELETE FROM totp_projection WHERE user_id = event.stream_id;

            UPDATE users_projection
            SET totp_enabled = FALSE,
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'TOTPBackupCodeUsed' THEN
            UPDATE totp_projection
            SET backup_codes_used[(event.data->>'index')::int + 1] = TRUE,
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE user_id = event.stream_id;

        WHEN 'TOTPBackupCodesRegenerated' THEN
            UPDATE totp_projection
            SET backup_codes_hash = ARRAY(SELECT jsonb_array_elements_text(event.data->'backup_codes_hash')),
                backup_codes_used = ARRAY(SELECT FALSE FROM jsonb_array_elements_text(event.data->'backup_codes_hash')),
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE user_id = event.stream_id;

        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- 4. project_user_group_event (MERGED: dynamic support from 015 + description fix from 014 + SCIM cleanup from 013)
-- Handles: UserGroupCreated, UserGroupUpdated, UserGroupQueryUpdated, UserGroupDeleted,
--          UserGroupMemberAdded, UserGroupMemberRemoved, UserGroupRoleAssigned, UserGroupRoleRevoked,
--          UserGroupMembersRebuilt
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_user_group_event(event events) RETURNS void AS $$
DECLARE
    is_dyn BOOLEAN;
BEGIN
    CASE event.event_type
        WHEN 'UserGroupCreated' THEN
            is_dyn := COALESCE((event.data->>'is_dynamic')::BOOLEAN, FALSE);
            INSERT INTO user_groups_projection (
                id, name, description, member_count,
                created_at, created_by, updated_at, projection_version,
                is_dynamic, dynamic_query
            ) VALUES (
                event.stream_id,
                event.data->>'name',
                COALESCE(event.data->>'description', ''),
                0,
                event.occurred_at,
                event.actor_id,
                event.occurred_at,
                event.sequence_num,
                is_dyn,
                event.data->>'dynamic_query'
            );

            IF is_dyn THEN
                INSERT INTO dynamic_user_group_evaluation_queue (group_id, reason)
                VALUES (event.stream_id, 'group_created')
                ON CONFLICT (group_id) DO UPDATE SET queued_at = NOW();
            END IF;

        WHEN 'UserGroupUpdated' THEN
            UPDATE user_groups_projection
            SET name = event.data->>'name',
                description = COALESCE(event.data->>'description', description),
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'UserGroupQueryUpdated' THEN
            is_dyn := COALESCE((event.data->>'is_dynamic')::BOOLEAN, FALSE);
            UPDATE user_groups_projection
            SET is_dynamic = is_dyn,
                dynamic_query = event.data->>'dynamic_query',
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

            IF is_dyn THEN
                -- Clear existing members and re-evaluate
                DELETE FROM user_group_members_projection WHERE group_id = event.stream_id;
                UPDATE user_groups_projection SET member_count = 0 WHERE id = event.stream_id;
                INSERT INTO dynamic_user_group_evaluation_queue (group_id, reason)
                VALUES (event.stream_id, 'query_updated')
                ON CONFLICT (group_id) DO UPDATE SET queued_at = NOW();
            END IF;

        WHEN 'UserGroupDeleted' THEN
            -- Clean up SCIM group mappings that reference this group
            DELETE FROM scim_group_mapping_projection WHERE user_group_id = event.stream_id;

            UPDATE user_groups_projection
            SET is_deleted = TRUE,
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

            -- Clean up members, roles, and evaluation queue
            DELETE FROM user_group_members_projection WHERE group_id = event.stream_id;
            DELETE FROM user_group_roles_projection WHERE group_id = event.stream_id;
            DELETE FROM dynamic_user_group_evaluation_queue WHERE group_id = event.stream_id;

        WHEN 'UserGroupMemberAdded' THEN
            -- Skip if group is dynamic (membership managed by query engine)
            IF NOT EXISTS (
                SELECT 1 FROM user_groups_projection
                WHERE id = event.data->>'group_id' AND is_dynamic = TRUE
            ) THEN
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
            END IF;

        WHEN 'UserGroupMemberRemoved' THEN
            -- Skip if group is dynamic
            IF NOT EXISTS (
                SELECT 1 FROM user_groups_projection
                WHERE id = event.data->>'group_id' AND is_dynamic = TRUE
            ) THEN
                DELETE FROM user_group_members_projection
                WHERE group_id = event.data->>'group_id'
                  AND user_id = event.data->>'user_id';

                UPDATE user_groups_projection
                SET member_count = GREATEST(member_count - 1, 0),
                    updated_at = event.occurred_at,
                    projection_version = event.sequence_num
                WHERE id = event.data->>'group_id';
            END IF;

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

        WHEN 'UserGroupMembersRebuilt' THEN
            -- Replace all members for this group (used by dynamic group evaluation)
            DELETE FROM user_group_members_projection WHERE group_id = event.stream_id;

            INSERT INTO user_group_members_projection (group_id, user_id, added_at, added_by, projection_version)
            SELECT event.stream_id, uid, event.occurred_at, 'system', event.sequence_num
            FROM jsonb_array_elements_text(event.data->'user_ids') AS uid
            ON CONFLICT (group_id, user_id) DO NOTHING;

            UPDATE user_groups_projection
            SET member_count = COALESCE(jsonb_array_length(event.data->'user_ids'), 0),
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- 5. project_identity_provider_event (from 012_scim.sql)
-- Handles: IdentityProviderCreated, IdentityProviderUpdated, IdentityProviderDeleted,
--          IdentityProviderSCIMEnabled, IdentityProviderSCIMDisabled, IdentityProviderSCIMTokenRotated,
--          IdentityLinked, IdentityLinkLoginUpdated, IdentityUnlinked
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_identity_provider_event(event events) RETURNS void AS $$
BEGIN
    CASE event.event_type
        WHEN 'IdentityProviderCreated' THEN
            INSERT INTO identity_providers_projection (
                id, name, slug, provider_type, enabled,
                client_id, client_secret_encrypted,
                issuer_url, authorization_url, token_url, userinfo_url,
                scopes, auto_create_users, auto_link_by_email,
                default_role_id, disable_password_for_linked,
                group_claim, group_mapping,
                created_at, created_by, updated_at, projection_version
            ) VALUES (
                event.stream_id,
                event.data->>'name',
                event.data->>'slug',
                COALESCE(event.data->>'provider_type', 'oidc'),
                TRUE,
                event.data->>'client_id',
                COALESCE(event.data->>'client_secret_encrypted', ''),
                event.data->>'issuer_url',
                COALESCE(event.data->>'authorization_url', ''),
                COALESCE(event.data->>'token_url', ''),
                COALESCE(event.data->>'userinfo_url', ''),
                CASE WHEN jsonb_typeof(event.data->'scopes') = 'array' THEN ARRAY(SELECT jsonb_array_elements_text(event.data->'scopes')) ELSE '{}' END,
                COALESCE((event.data->>'auto_create_users')::BOOLEAN, FALSE),
                COALESCE((event.data->>'auto_link_by_email')::BOOLEAN, FALSE),
                COALESCE(event.data->>'default_role_id', ''),
                COALESCE((event.data->>'disable_password_for_linked')::BOOLEAN, FALSE),
                COALESCE(event.data->>'group_claim', ''),
                COALESCE((event.data->'group_mapping')::JSONB, '{}'),
                event.occurred_at,
                event.actor_id,
                event.occurred_at,
                event.sequence_num
            );

        WHEN 'IdentityProviderUpdated' THEN
            UPDATE identity_providers_projection
            SET name = COALESCE(event.data->>'name', name),
                enabled = COALESCE((event.data->>'enabled')::BOOLEAN, enabled),
                client_id = COALESCE(NULLIF(event.data->>'client_id', ''), client_id),
                client_secret_encrypted = COALESCE(NULLIF(event.data->>'client_secret_encrypted', ''), client_secret_encrypted),
                issuer_url = COALESCE(NULLIF(event.data->>'issuer_url', ''), issuer_url),
                authorization_url = COALESCE(event.data->>'authorization_url', authorization_url),
                token_url = COALESCE(event.data->>'token_url', token_url),
                userinfo_url = COALESCE(event.data->>'userinfo_url', userinfo_url),
                scopes = CASE WHEN jsonb_typeof(event.data->'scopes') = 'array' THEN ARRAY(SELECT jsonb_array_elements_text(event.data->'scopes')) ELSE scopes END,
                auto_create_users = COALESCE((event.data->>'auto_create_users')::BOOLEAN, auto_create_users),
                auto_link_by_email = COALESCE((event.data->>'auto_link_by_email')::BOOLEAN, auto_link_by_email),
                default_role_id = COALESCE(event.data->>'default_role_id', default_role_id),
                disable_password_for_linked = COALESCE((event.data->>'disable_password_for_linked')::BOOLEAN, disable_password_for_linked),
                group_claim = COALESCE(event.data->>'group_claim', group_claim),
                group_mapping = COALESCE((event.data->'group_mapping')::JSONB, group_mapping),
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'IdentityProviderDeleted' THEN
            UPDATE identity_providers_projection
            SET is_deleted = TRUE,
                enabled = FALSE,
                scim_enabled = FALSE,
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

            -- Clean up identity links and SCIM group mappings for this provider
            DELETE FROM identity_links_projection WHERE provider_id = event.stream_id;
            DELETE FROM scim_group_mapping_projection WHERE provider_id = event.stream_id;

        WHEN 'IdentityProviderSCIMEnabled' THEN
            UPDATE identity_providers_projection
            SET scim_enabled = TRUE,
                scim_token_hash = event.data->>'scim_token_hash',
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'IdentityProviderSCIMDisabled' THEN
            UPDATE identity_providers_projection
            SET scim_enabled = FALSE,
                scim_token_hash = '',
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

            -- Clean up SCIM group mappings
            DELETE FROM scim_group_mapping_projection WHERE provider_id = event.stream_id;

        WHEN 'IdentityProviderSCIMTokenRotated' THEN
            UPDATE identity_providers_projection
            SET scim_token_hash = event.data->>'scim_token_hash',
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'IdentityLinked' THEN
            INSERT INTO identity_links_projection (
                id, user_id, provider_id, external_id,
                external_email, external_name,
                linked_at, last_login_at, projection_version
            ) VALUES (
                event.stream_id,
                event.data->>'user_id',
                event.data->>'provider_id',
                event.data->>'external_id',
                COALESCE(event.data->>'external_email', ''),
                COALESCE(event.data->>'external_name', ''),
                event.occurred_at,
                event.occurred_at,
                event.sequence_num
            )
            ON CONFLICT (provider_id, external_id) DO UPDATE SET
                external_email = EXCLUDED.external_email,
                external_name = EXCLUDED.external_name,
                last_login_at = EXCLUDED.last_login_at,
                projection_version = EXCLUDED.projection_version;

        WHEN 'IdentityLinkLoginUpdated' THEN
            UPDATE identity_links_projection
            SET last_login_at = event.occurred_at,
                external_email = COALESCE(NULLIF(event.data->>'external_email', ''), external_email),
                external_name = COALESCE(NULLIF(event.data->>'external_name', ''), external_name),
                projection_version = event.sequence_num
            WHERE provider_id = event.data->>'provider_id'
              AND external_id = event.data->>'external_id';

        WHEN 'IdentityUnlinked' THEN
            DELETE FROM identity_links_projection
            WHERE id = event.stream_id;

        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- 6. project_scim_group_mapping_event (from 012_scim.sql)
-- Handles: SCIMGroupMapped, SCIMGroupUnmapped, SCIMGroupMappingUpdated
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_scim_group_mapping_event(event events) RETURNS void AS $$
BEGIN
    CASE event.event_type
        WHEN 'SCIMGroupMapped' THEN
            INSERT INTO scim_group_mapping_projection (
                id, provider_id, scim_group_id, scim_display_name,
                user_group_id, created_at, projection_version
            ) VALUES (
                event.stream_id,
                event.data->>'provider_id',
                event.data->>'scim_group_id',
                COALESCE(event.data->>'scim_display_name', ''),
                event.data->>'user_group_id',
                event.occurred_at,
                event.sequence_num
            )
            ON CONFLICT (provider_id, scim_group_id) DO UPDATE SET
                scim_display_name = EXCLUDED.scim_display_name,
                user_group_id = EXCLUDED.user_group_id,
                projection_version = EXCLUDED.projection_version;

        WHEN 'SCIMGroupUnmapped' THEN
            DELETE FROM scim_group_mapping_projection
            WHERE provider_id = event.data->>'provider_id'
              AND scim_group_id = event.data->>'scim_group_id';

        WHEN 'SCIMGroupMappingUpdated' THEN
            UPDATE scim_group_mapping_projection
            SET scim_display_name = COALESCE(event.data->>'scim_display_name', scim_display_name),
                projection_version = event.sequence_num
            WHERE provider_id = event.data->>'provider_id'
              AND scim_group_id = event.data->>'scim_group_id';

        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- 7. recalculate_device_compliance (from 017_compliance.sql)
-- Helper function to recalculate device compliance summary from its checks
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION recalculate_device_compliance(p_device_id TEXT) RETURNS void AS $$
DECLARE
    v_total INTEGER;
    v_passing INTEGER;
    v_status INTEGER;
BEGIN
    SELECT COUNT(*), COUNT(*) FILTER (WHERE compliant = TRUE)
    INTO v_total, v_passing
    FROM compliance_results_projection
    WHERE device_id = p_device_id;

    IF v_total = 0 THEN
        v_status := 0; -- UNKNOWN
    ELSIF v_passing = v_total THEN
        v_status := 1; -- COMPLIANT
    ELSE
        v_status := 2; -- NON_COMPLIANT
    END IF;

    UPDATE devices_projection SET
        compliance_status = v_status,
        compliance_checked_at = NOW(),
        compliance_total = v_total,
        compliance_passing = v_passing
    WHERE id = p_device_id;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- 8. evaluate_device_compliance_policies (from 018_compliance_policies.sql)
-- Evaluates all compliance policies for a device
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION evaluate_device_compliance_policies(p_device_id TEXT) RETURNS void AS $$
DECLARE
    v_rule RECORD;
    v_result RECORD;
    v_rule_status INTEGER;
    v_has_policies BOOLEAN := FALSE;
    v_all_compliant BOOLEAN := TRUE;
    v_any_in_grace BOOLEAN := FALSE;
    v_any_non_compliant BOOLEAN := FALSE;
    v_total INTEGER := 0;
    v_passing INTEGER := 0;
    v_overall_status INTEGER;
    v_existing_first_failed TIMESTAMPTZ;
BEGIN
    -- Iterate over all rules from all policies assigned to this device
    FOR v_rule IN
        SELECT r.policy_id, r.action_id, r.grace_period_hours
        FROM compliance_policy_rules_projection r
        JOIN compliance_policies_projection p ON p.id = r.policy_id AND p.is_deleted = FALSE
        JOIN assignments_projection a ON a.source_type = 'compliance_policy'
            AND a.source_id = r.policy_id AND a.is_deleted = FALSE
        WHERE (
            (a.target_type = 'device' AND a.target_id = p_device_id)
            OR (a.target_type = 'device_group' AND a.target_id IN (
                SELECT group_id FROM device_group_members_projection
                WHERE device_id = p_device_id
            ))
        )
    LOOP
        v_has_policies := TRUE;
        v_total := v_total + 1;

        -- Look up the latest compliance result for this action on this device
        SELECT compliant, checked_at
        INTO v_result
        FROM compliance_results_projection
        WHERE device_id = p_device_id AND action_id = v_rule.action_id;

        IF NOT FOUND THEN
            -- No result yet: unknown
            v_rule_status := 0; -- UNKNOWN
            v_all_compliant := FALSE;

            INSERT INTO compliance_policy_evaluation_projection (
                device_id, policy_id, action_id, compliant, first_failed_at,
                status, checked_at, projection_version
            ) VALUES (
                p_device_id, v_rule.policy_id, v_rule.action_id,
                FALSE, NULL, 0, NULL, 0
            ) ON CONFLICT (device_id, policy_id, action_id) DO UPDATE SET
                compliant = FALSE,
                status = 0,
                projection_version = 0;

        ELSIF v_result.compliant THEN
            -- Compliant: clear first_failed_at
            v_rule_status := 1; -- COMPLIANT
            v_passing := v_passing + 1;

            INSERT INTO compliance_policy_evaluation_projection (
                device_id, policy_id, action_id, compliant, first_failed_at,
                status, checked_at, projection_version
            ) VALUES (
                p_device_id, v_rule.policy_id, v_rule.action_id,
                TRUE, NULL, 1, v_result.checked_at, 0
            ) ON CONFLICT (device_id, policy_id, action_id) DO UPDATE SET
                compliant = TRUE,
                first_failed_at = NULL,
                status = 1,
                checked_at = v_result.checked_at;

        ELSE
            -- Non-compliant: check grace period
            SELECT first_failed_at INTO v_existing_first_failed
            FROM compliance_policy_evaluation_projection
            WHERE device_id = p_device_id
              AND policy_id = v_rule.policy_id
              AND action_id = v_rule.action_id;

            IF v_existing_first_failed IS NULL THEN
                -- First failure: record timestamp
                v_existing_first_failed := NOW();
            END IF;

            IF v_rule.grace_period_hours > 0
               AND (NOW() - v_existing_first_failed) < (v_rule.grace_period_hours || ' hours')::INTERVAL
            THEN
                -- Within grace period
                v_rule_status := 3; -- IN_GRACE_PERIOD
                v_any_in_grace := TRUE;
            ELSE
                -- Past grace period (or no grace period)
                v_rule_status := 2; -- NON_COMPLIANT
                v_any_non_compliant := TRUE;
                v_all_compliant := FALSE;
            END IF;

            INSERT INTO compliance_policy_evaluation_projection (
                device_id, policy_id, action_id, compliant, first_failed_at,
                status, checked_at, projection_version
            ) VALUES (
                p_device_id, v_rule.policy_id, v_rule.action_id,
                FALSE, v_existing_first_failed, v_rule_status,
                v_result.checked_at, 0
            ) ON CONFLICT (device_id, policy_id, action_id) DO UPDATE SET
                compliant = FALSE,
                first_failed_at = COALESCE(
                    compliance_policy_evaluation_projection.first_failed_at,
                    v_existing_first_failed
                ),
                status = v_rule_status,
                checked_at = v_result.checked_at;
        END IF;
    END LOOP;

    -- If no policies assigned, fall back to existing simple compliance
    IF NOT v_has_policies THEN
        PERFORM recalculate_device_compliance(p_device_id);
        RETURN;
    END IF;

    -- Compute overall device status
    IF v_any_non_compliant THEN
        v_overall_status := 2; -- NON_COMPLIANT
    ELSIF v_any_in_grace THEN
        v_overall_status := 3; -- IN_GRACE_PERIOD
    ELSIF v_all_compliant AND v_total > 0 THEN
        v_overall_status := 1; -- COMPLIANT
    ELSE
        v_overall_status := 0; -- UNKNOWN
    END IF;

    UPDATE devices_projection SET
        compliance_status = v_overall_status,
        compliance_checked_at = NOW(),
        compliance_total = v_total,
        compliance_passing = v_passing
    WHERE id = p_device_id;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- 9. reevaluate_compliance_policy_devices (from 028_fix_compliance_evaluation.sql)
-- Re-evaluates a specific compliance policy across all affected devices
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION reevaluate_compliance_policy_devices(p_policy_id TEXT) RETURNS void AS $$
DECLARE
    v_device_id TEXT;
BEGIN
    FOR v_device_id IN
        SELECT a.target_id
        FROM assignments_projection a
        WHERE a.source_type = 'compliance_policy'
          AND a.source_id = p_policy_id
          AND a.target_type = 'device'
          AND a.is_deleted = FALSE
        UNION
        SELECT dgm.device_id
        FROM assignments_projection a
        JOIN device_group_members_projection dgm ON dgm.group_id = a.target_id
        WHERE a.source_type = 'compliance_policy'
          AND a.source_id = p_policy_id
          AND a.target_type = 'device_group'
          AND a.is_deleted = FALSE
    LOOP
        PERFORM evaluate_device_compliance_policies(v_device_id);
    END LOOP;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- 10. project_compliance_event (from 018_compliance_policies.sql)
-- Handles: ComplianceResultUpdated, ComplianceResultRemoved
-- Calls evaluate_device_compliance_policies (falls back to simple check if no policies)
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_compliance_event(event events) RETURNS void AS $$
BEGIN
    CASE event.event_type
        WHEN 'ComplianceResultUpdated' THEN
            INSERT INTO compliance_results_projection (
                device_id, action_id, action_name, compliant, detection_output,
                checked_at, projection_version
            ) VALUES (
                event.data->>'device_id',
                event.data->>'action_id',
                COALESCE(event.data->>'action_name', ''),
                COALESCE((event.data->>'compliant')::boolean, false),
                event.data->'detection_output',
                event.occurred_at,
                event.sequence_num
            )
            ON CONFLICT (device_id, action_id) DO UPDATE SET
                action_name = COALESCE(event.data->>'action_name', compliance_results_projection.action_name),
                compliant = COALESCE((event.data->>'compliant')::boolean, false),
                detection_output = event.data->'detection_output',
                checked_at = event.occurred_at,
                projection_version = event.sequence_num;

            -- Evaluate compliance policies (falls back to simple check if no policies assigned)
            PERFORM evaluate_device_compliance_policies(event.data->>'device_id');

        WHEN 'ComplianceResultRemoved' THEN
            DELETE FROM compliance_results_projection
            WHERE device_id = event.data->>'device_id'
              AND action_id = event.data->>'action_id';

            -- Re-evaluate compliance policies
            PERFORM evaluate_device_compliance_policies(event.data->>'device_id');

        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- 11. project_compliance_policy_event (from 028_fix_compliance_evaluation.sql)
-- Handles: CompliancePolicyCreated, CompliancePolicyRenamed, CompliancePolicyDescriptionUpdated,
--          CompliancePolicyDeleted, CompliancePolicyRuleAdded, CompliancePolicyRuleRemoved,
--          CompliancePolicyRuleUpdated
-- Includes re-evaluation via reevaluate_compliance_policy_devices on delete and rule removal
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_compliance_policy_event(event events) RETURNS void AS $$
BEGIN
    CASE event.event_type
        WHEN 'CompliancePolicyCreated' THEN
            INSERT INTO compliance_policies_projection (
                id, name, description, rule_count, created_at,
                created_by, projection_version
            ) VALUES (
                event.stream_id,
                event.data->>'name',
                COALESCE(event.data->>'description', ''),
                0,
                event.occurred_at,
                event.actor_id,
                event.sequence_num
            );

        WHEN 'CompliancePolicyRenamed' THEN
            UPDATE compliance_policies_projection
            SET name = event.data->>'name',
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'CompliancePolicyDescriptionUpdated' THEN
            UPDATE compliance_policies_projection
            SET description = COALESCE(event.data->>'description', ''),
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'CompliancePolicyDeleted' THEN
            UPDATE compliance_policies_projection
            SET is_deleted = TRUE,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

            DELETE FROM compliance_policy_rules_projection WHERE policy_id = event.stream_id;
            DELETE FROM compliance_policy_evaluation_projection WHERE policy_id = event.stream_id;

            -- Re-evaluate affected devices to update their overall status
            PERFORM reevaluate_compliance_policy_devices(event.stream_id);

        WHEN 'CompliancePolicyRuleAdded' THEN
            INSERT INTO compliance_policy_rules_projection (
                policy_id, action_id, action_name, grace_period_hours,
                added_at, projection_version
            ) VALUES (
                event.stream_id,
                event.data->>'action_id',
                COALESCE(event.data->>'action_name', ''),
                COALESCE((event.data->>'grace_period_hours')::INTEGER, 0),
                event.occurred_at,
                event.sequence_num
            ) ON CONFLICT (policy_id, action_id) DO UPDATE SET
                action_name = COALESCE(event.data->>'action_name',
                    compliance_policy_rules_projection.action_name),
                grace_period_hours = COALESCE(
                    (event.data->>'grace_period_hours')::INTEGER, 0),
                projection_version = event.sequence_num;

            UPDATE compliance_policies_projection
            SET rule_count = (
                SELECT COUNT(*) FROM compliance_policy_rules_projection
                WHERE policy_id = event.stream_id
            ), projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'CompliancePolicyRuleRemoved' THEN
            DELETE FROM compliance_policy_rules_projection
            WHERE policy_id = event.stream_id
              AND action_id = event.data->>'action_id';

            UPDATE compliance_policies_projection
            SET rule_count = (
                SELECT COUNT(*) FROM compliance_policy_rules_projection
                WHERE policy_id = event.stream_id
            ), projection_version = event.sequence_num
            WHERE id = event.stream_id;

            DELETE FROM compliance_policy_evaluation_projection
            WHERE policy_id = event.stream_id
              AND action_id = event.data->>'action_id';

            -- Re-evaluate affected devices to update their overall status
            PERFORM reevaluate_compliance_policy_devices(event.stream_id);

        WHEN 'CompliancePolicyRuleUpdated' THEN
            UPDATE compliance_policy_rules_projection
            SET grace_period_hours = COALESCE(
                    (event.data->>'grace_period_hours')::INTEGER, 0),
                projection_version = event.sequence_num
            WHERE policy_id = event.stream_id
              AND action_id = event.data->>'action_id';

        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- 12. project_lps_password_event (from 027_fix_lps_current_scope.sql)
-- Scoped by (device_id, username) NOT (device_id, action_id, username)
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_lps_password_event(event events) RETURNS void AS $$
BEGIN
    CASE event.event_type
        WHEN 'LpsPasswordRotated' THEN
            -- Mark ALL previous passwords as not current for this device+username
            UPDATE lps_passwords_projection
            SET is_current = FALSE
            WHERE device_id = event.data->>'device_id'
              AND username = event.data->>'username';

            -- Insert new password
            INSERT INTO lps_passwords_projection
                (device_id, action_id, username, password, rotated_at, rotation_reason)
            VALUES (
                event.data->>'device_id',
                event.data->>'action_id',
                event.data->>'username',
                event.data->>'password',
                (event.data->>'rotated_at')::TIMESTAMPTZ,
                COALESCE(event.data->>'rotation_reason', 'scheduled')
            );

            -- Keep only last 3 passwords per device+username
            DELETE FROM lps_passwords_projection
            WHERE id NOT IN (
                SELECT id FROM lps_passwords_projection
                WHERE device_id = event.data->>'device_id'
                  AND username = event.data->>'username'
                ORDER BY rotated_at DESC LIMIT 3
            )
            AND device_id = event.data->>'device_id'
            AND username = event.data->>'username';
        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- 13. project_luks_key_event (from 005_luks_revocation.sql)
-- Handles: LuksKeyRotated, LuksDeviceKeyRevocationDispatched, LuksDeviceKeyRevoked, LuksDeviceKeyRevocationFailed
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_luks_key_event(event events) RETURNS void AS $$
BEGIN
    CASE event.event_type
        WHEN 'LuksKeyRotated' THEN
            -- Mark previous keys as not current for this device+action+device_path
            UPDATE luks_keys_projection
            SET is_current = FALSE
            WHERE device_id = event.data->>'device_id'
              AND action_id = event.data->>'action_id'
              AND device_path = event.data->>'device_path';

            -- Insert new key (revocation resets on rotation)
            INSERT INTO luks_keys_projection
                (device_id, action_id, device_path, passphrase, rotated_at, rotation_reason)
            VALUES (
                event.data->>'device_id',
                event.data->>'action_id',
                event.data->>'device_path',
                event.data->>'passphrase',
                (event.data->>'rotated_at')::TIMESTAMPTZ,
                COALESCE(event.data->>'rotation_reason', 'scheduled')
            );

            -- Keep only last 3 keys per device+action+device_path
            DELETE FROM luks_keys_projection
            WHERE id NOT IN (
                SELECT id FROM luks_keys_projection
                WHERE device_id = event.data->>'device_id'
                  AND action_id = event.data->>'action_id'
                  AND device_path = event.data->>'device_path'
                ORDER BY rotated_at DESC LIMIT 3
            )
            AND device_id = event.data->>'device_id'
            AND action_id = event.data->>'action_id'
            AND device_path = event.data->>'device_path';

        WHEN 'LuksDeviceKeyRevocationDispatched' THEN
            UPDATE luks_keys_projection
            SET revocation_status = 'dispatched',
                revocation_error = NULL,
                revocation_at = (event.data->>'dispatched_at')::TIMESTAMPTZ
            WHERE device_id = event.data->>'device_id'
              AND action_id = event.data->>'action_id'
              AND is_current = TRUE;

        WHEN 'LuksDeviceKeyRevoked' THEN
            UPDATE luks_keys_projection
            SET revocation_status = 'success',
                revocation_error = NULL,
                revocation_at = (event.data->>'revoked_at')::TIMESTAMPTZ
            WHERE device_id = event.data->>'device_id'
              AND action_id = event.data->>'action_id'
              AND is_current = TRUE;

        WHEN 'LuksDeviceKeyRevocationFailed' THEN
            UPDATE luks_keys_projection
            SET revocation_status = 'failed',
                revocation_error = event.data->>'error',
                revocation_at = (event.data->>'failed_at')::TIMESTAMPTZ
            WHERE device_id = event.data->>'device_id'
              AND action_id = event.data->>'action_id'
              AND is_current = TRUE;

        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- 14. project_server_settings_event (from 020_server_settings.sql)
-- Handles: ServerSettingUpdated
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

-- +goose Down
-- Full teardown is handled by Part 5 down migration.
-- This stub exists for goose compatibility.
