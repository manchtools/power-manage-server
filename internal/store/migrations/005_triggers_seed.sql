-- +goose Up

-- ============================================================================
-- PART 5: MASTER PROJECTOR, TRIGGERS, REBUILD FUNCTIONS, SEED DATA
-- ============================================================================

-- ---------- MASTER EVENT DISPATCHER ----------

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

        WHEN 'lps_password' THEN
            BEGIN
                PERFORM project_lps_password_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        WHEN 'luks_key' THEN
            BEGIN
                PERFORM project_luks_key_event(NEW);
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

-- ============================================================================
-- TRIGGERS
-- ============================================================================

CREATE TRIGGER event_projector
    AFTER INSERT ON events
    FOR EACH ROW
    EXECUTE FUNCTION project_event();

CREATE TRIGGER device_label_change_trigger
    AFTER INSERT OR UPDATE OF labels ON devices_projection
    FOR EACH ROW
    EXECUTE FUNCTION trigger_device_label_change();

CREATE TRIGGER device_deleted_trigger
    AFTER UPDATE OF is_deleted ON devices_projection
    FOR EACH ROW
    EXECUTE FUNCTION trigger_device_deleted();

CREATE TRIGGER device_inventory_changed
    AFTER INSERT OR UPDATE ON device_inventory
    FOR EACH ROW
    EXECUTE FUNCTION trigger_inventory_change();

CREATE TRIGGER user_attribute_change_trigger
    AFTER INSERT OR UPDATE OF email, disabled, totp_enabled, has_password, is_deleted, display_name, preferred_username, locale
    ON users_projection
    FOR EACH ROW
    EXECUTE FUNCTION queue_dynamic_user_groups_on_user_change();

-- ============================================================================
-- REBUILD FUNCTIONS
-- ============================================================================

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION rebuild_users_projection() RETURNS void AS $$
DECLARE
    event_record events;
BEGIN
    TRUNCATE users_projection CASCADE;
    FOR event_record IN SELECT * FROM events WHERE stream_type = 'user' ORDER BY sequence_num LOOP
        PERFORM project_user_event(event_record);
    END LOOP;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION rebuild_tokens_projection() RETURNS void AS $$
DECLARE
    event_record events;
BEGIN
    TRUNCATE tokens_projection;
    FOR event_record IN SELECT * FROM events WHERE stream_type = 'token' ORDER BY sequence_num LOOP
        PERFORM project_token_event(event_record);
    END LOOP;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION rebuild_devices_projection() RETURNS void AS $$
DECLARE
    event_record events;
BEGIN
    TRUNCATE devices_projection CASCADE;
    TRUNCATE device_assigned_users_projection;
    TRUNCATE device_assigned_groups_projection;
    FOR event_record IN SELECT * FROM events WHERE stream_type = 'device' ORDER BY sequence_num LOOP
        PERFORM project_device_event(event_record);
    END LOOP;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION rebuild_actions_projection() RETURNS void AS $$
DECLARE
    event_record events;
BEGIN
    TRUNCATE actions_projection;
    FOR event_record IN SELECT * FROM events WHERE stream_type IN ('action', 'definition') ORDER BY sequence_num LOOP
        PERFORM project_action_event(event_record);
    END LOOP;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION rebuild_executions_projection() RETURNS void AS $$
DECLARE
    event_record events;
BEGIN
    TRUNCATE executions_projection;
    FOR event_record IN SELECT * FROM events WHERE stream_type = 'execution' ORDER BY sequence_num LOOP
        PERFORM project_execution_event(event_record);
    END LOOP;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION rebuild_action_sets_projection() RETURNS void AS $$
DECLARE
    event_record events;
BEGIN
    TRUNCATE action_sets_projection CASCADE;
    TRUNCATE action_set_members_projection;
    FOR event_record IN SELECT * FROM events WHERE stream_type = 'action_set' ORDER BY sequence_num LOOP
        PERFORM project_action_set_event(event_record);
    END LOOP;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION rebuild_definitions_projection() RETURNS void AS $$
DECLARE
    event_record events;
BEGIN
    TRUNCATE definitions_projection CASCADE;
    TRUNCATE definition_members_projection;
    FOR event_record IN SELECT * FROM events WHERE stream_type = 'definition' ORDER BY sequence_num LOOP
        PERFORM project_definition_event(event_record);
    END LOOP;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION rebuild_device_groups_projection() RETURNS void AS $$
DECLARE
    event_record events;
BEGIN
    TRUNCATE device_groups_projection CASCADE;
    TRUNCATE device_group_members_projection;
    TRUNCATE dynamic_group_evaluation_queue;
    FOR event_record IN SELECT * FROM events WHERE stream_type = 'device_group' ORDER BY sequence_num LOOP
        PERFORM project_device_group_event(event_record);
    END LOOP;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION rebuild_assignments_projection() RETURNS void AS $$
DECLARE
    event_record events;
BEGIN
    TRUNCATE assignments_projection;
    FOR event_record IN SELECT * FROM events WHERE stream_type = 'assignment' ORDER BY sequence_num LOOP
        PERFORM project_assignment_event(event_record);
    END LOOP;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION rebuild_user_selections_projection() RETURNS void AS $$
DECLARE
    event_record events;
BEGIN
    TRUNCATE user_selections_projection;
    FOR event_record IN SELECT * FROM events WHERE stream_type = 'user_selection' ORDER BY sequence_num LOOP
        PERFORM project_user_selection_event(event_record);
    END LOOP;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION rebuild_roles_projection() RETURNS void AS $$
DECLARE
    event_record events;
BEGIN
    TRUNCATE roles_projection CASCADE;
    TRUNCATE user_roles_projection;
    FOR event_record IN SELECT * FROM events WHERE stream_type = 'role' ORDER BY sequence_num LOOP
        PERFORM project_role_event(event_record);
    END LOOP;
    FOR event_record IN SELECT * FROM events WHERE stream_type = 'user_role' ORDER BY sequence_num LOOP
        PERFORM project_user_role_event(event_record);
    END LOOP;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION rebuild_user_groups_projection() RETURNS void AS $$
DECLARE
    event_record events;
BEGIN
    TRUNCATE user_groups_projection CASCADE;
    TRUNCATE user_group_members_projection;
    TRUNCATE user_group_roles_projection;
    TRUNCATE dynamic_user_group_evaluation_queue;
    FOR event_record IN SELECT * FROM events WHERE stream_type = 'user_group' ORDER BY sequence_num LOOP
        PERFORM project_user_group_event(event_record);
    END LOOP;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION rebuild_all_projections() RETURNS void AS $$
BEGIN
    PERFORM rebuild_users_projection();
    PERFORM rebuild_tokens_projection();
    PERFORM rebuild_devices_projection();
    PERFORM rebuild_actions_projection();
    PERFORM rebuild_executions_projection();
    PERFORM rebuild_action_sets_projection();
    PERFORM rebuild_definitions_projection();
    PERFORM rebuild_device_groups_projection();
    PERFORM rebuild_assignments_projection();
    PERFORM rebuild_user_selections_projection();
    PERFORM rebuild_roles_projection();
    PERFORM rebuild_user_groups_projection();
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- ============================================================================
-- SEED DATA: SYSTEM ROLES
-- ============================================================================

-- Admin role: all base (unrestricted) permissions
INSERT INTO roles_projection (id, name, description, permissions, is_system, created_at, updated_at, projection_version)
VALUES (
    '00000000000000000000000001', 'Admin', 'Full system access',
    '{GetCurrentUser,GetUser,ListUsers,CreateUser,UpdateUserEmail,UpdateUserPassword,SetUserDisabled,UpdateUserProfile,DeleteUser,UpdateUserSshSettings,AddUserSshKey,RemoveUserSshKey,ListDevices,GetDevice,SetDeviceLabel,RemoveDeviceLabel,AssignDevice,UnassignDevice,ListDeviceAssignees,SetDeviceSyncInterval,DeleteDevice,CreateToken,GetToken,ListTokens,RenameToken,SetTokenDisabled,DeleteToken,CreateAction,GetAction,ListActions,RenameAction,UpdateActionDescription,UpdateActionParams,DeleteAction,CreateActionSet,GetActionSet,ListActionSets,RenameActionSet,UpdateActionSetDescription,DeleteActionSet,AddActionToSet,RemoveActionFromSet,ReorderActionInSet,CreateDefinition,GetDefinition,ListDefinitions,RenameDefinition,UpdateDefinitionDescription,DeleteDefinition,AddActionSetToDefinition,RemoveActionSetFromDefinition,ReorderActionSetInDefinition,CreateDeviceGroup,GetDeviceGroup,ListDeviceGroups,ListDeviceGroupsForDevice,RenameDeviceGroup,UpdateDeviceGroupDescription,UpdateDeviceGroupQuery,DeleteDeviceGroup,AddDeviceToGroup,RemoveDeviceFromGroup,ValidateDynamicQuery,EvaluateDynamicGroup,SetDeviceGroupSyncInterval,CreateAssignment,DeleteAssignment,ListAssignments,GetDeviceAssignments,GetUserAssignments,SetUserSelection,ListAvailableActions,DispatchAction,DispatchToMultiple,DispatchAssignedActions,DispatchActionSet,DispatchDefinition,DispatchToGroup,DispatchInstantAction,GetExecution,ListExecutions,DispatchOSQuery,GetOSQueryResult,GetDeviceInventory,RefreshDeviceInventory,QueryDeviceLogs,GetDeviceLogResult,GetDeviceCompliance,CreateCompliancePolicy,GetCompliancePolicy,ListCompliancePolicies,RenameCompliancePolicy,UpdateCompliancePolicyDescription,DeleteCompliancePolicy,AddCompliancePolicyRule,RemoveCompliancePolicyRule,UpdateCompliancePolicyRule,GetDeviceCompliancePolicyStatus,ListAuditEvents,GetDeviceLpsPasswords,GetDeviceLuksKeys,CreateLuksToken,RevokeLuksDeviceKey,SetupTOTP,VerifyTOTP,DisableTOTP,AdminDisableUserTOTP,GetTOTPStatus,RegenerateBackupCodes,CreateRole,GetRole,ListRoles,UpdateRole,DeleteRole,AssignRoleToUser,RevokeRoleFromUser,ListPermissions,CreateUserGroup,GetUserGroup,ListUserGroups,UpdateUserGroup,DeleteUserGroup,AddUserToGroup,RemoveUserFromGroup,AssignRoleToUserGroup,RevokeRoleFromUserGroup,ListUserGroupsForUser,UpdateUserGroupQuery,ValidateUserGroupQuery,EvaluateDynamicUserGroup,CreateIdentityProvider,GetIdentityProvider,ListIdentityProviders,UpdateIdentityProvider,DeleteIdentityProvider,EnableSCIM,DisableSCIM,RotateSCIMToken,ListIdentityLinks,UnlinkIdentity,Search,RebuildSearchIndex,GetServerSettings,UpdateServerSettings,SetUserProvisioningEnabled}',
    TRUE, NOW(), NOW(), 0
);

-- User role: self-service permissions
INSERT INTO roles_projection (id, name, description, permissions, is_system, created_at, updated_at, projection_version)
VALUES (
    '00000000000000000000000002', 'User', 'Basic user access',
    '{GetCurrentUser,GetUser:self,UpdateUserEmail:self,UpdateUserPassword:self,UpdateUserProfile:self,SetupTOTP,VerifyTOTP,DisableTOTP,GetTOTPStatus,RegenerateBackupCodes,ListDevices:assigned,GetDevice:assigned,CreateToken:self,SetUserSelection,ListAvailableActions,ListIdentityLinks,UnlinkIdentity,GetDeviceCompliance:assigned,AddUserSshKey:self,RemoveUserSshKey:self}',
    TRUE, NOW(), NOW(), 0
);

-- ============================================================================
-- SEED DATA: "ALL DEVICES" DYNAMIC GROUP
-- ============================================================================

-- +goose StatementBegin
DO $$
DECLARE
    group_id TEXT;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM device_groups_projection WHERE name = 'All Devices' AND is_deleted = FALSE) THEN
        group_id := generate_ulid();
        INSERT INTO events (stream_type, stream_id, stream_version, event_type, data, actor_type, actor_id)
        VALUES (
            'device_group', group_id, 1, 'DeviceGroupCreated',
            jsonb_build_object(
                'name', 'All Devices',
                'description', 'Dynamic group that matches all registered devices',
                'is_dynamic', true,
                'dynamic_query', ''
            ),
            'system', 'migration'
        );
    END IF;
END;
$$;
-- +goose StatementEnd

-- ============================================================================
-- DATABASE ROLES
-- ============================================================================

-- +goose StatementBegin
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'pm_readonly') THEN
        CREATE ROLE pm_readonly NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'pm_indexer') THEN
        CREATE ROLE pm_indexer LOGIN;
    END IF;
END
$$;
-- +goose StatementEnd

GRANT pm_readonly TO pm_indexer;
GRANT USAGE ON SCHEMA public TO pm_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO pm_readonly;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO pm_readonly;

-- ============================================================================
-- DOWN MIGRATION
-- ============================================================================

-- +goose Down

-- +goose StatementBegin

-- Drop triggers
DROP TRIGGER IF EXISTS user_attribute_change_trigger ON users_projection;
DROP TRIGGER IF EXISTS device_inventory_changed ON device_inventory;
DROP TRIGGER IF EXISTS device_deleted_trigger ON devices_projection;
DROP TRIGGER IF EXISTS device_label_change_trigger ON devices_projection;
DROP TRIGGER IF EXISTS event_projector ON events;

-- Drop rebuild functions
DROP FUNCTION IF EXISTS rebuild_all_projections;
DROP FUNCTION IF EXISTS rebuild_user_groups_projection;
DROP FUNCTION IF EXISTS rebuild_roles_projection;
DROP FUNCTION IF EXISTS rebuild_user_selections_projection;
DROP FUNCTION IF EXISTS rebuild_assignments_projection;
DROP FUNCTION IF EXISTS rebuild_device_groups_projection;
DROP FUNCTION IF EXISTS rebuild_definitions_projection;
DROP FUNCTION IF EXISTS rebuild_action_sets_projection;
DROP FUNCTION IF EXISTS rebuild_executions_projection;
DROP FUNCTION IF EXISTS rebuild_actions_projection;
DROP FUNCTION IF EXISTS rebuild_devices_projection;
DROP FUNCTION IF EXISTS rebuild_tokens_projection;
DROP FUNCTION IF EXISTS rebuild_users_projection;

-- Drop master projector
DROP FUNCTION IF EXISTS project_event;

-- Drop utility functions
DROP FUNCTION IF EXISTS get_stream_at;
DROP FUNCTION IF EXISTS get_device_sync_interval;

-- Drop user group dynamic functions
DROP FUNCTION IF EXISTS validate_user_group_query;
DROP FUNCTION IF EXISTS queue_dynamic_user_groups_on_user_change;
DROP FUNCTION IF EXISTS evaluate_queued_dynamic_user_groups;
DROP FUNCTION IF EXISTS evaluate_dynamic_user_group;
DROP FUNCTION IF EXISTS evaluate_dynamic_user_query;
DROP FUNCTION IF EXISTS evaluate_user_condition;

-- Drop device group dynamic functions
DROP FUNCTION IF EXISTS validate_dynamic_query;
DROP FUNCTION IF EXISTS trigger_inventory_change;
DROP FUNCTION IF EXISTS trigger_device_deleted;
DROP FUNCTION IF EXISTS trigger_device_label_change;
DROP FUNCTION IF EXISTS queue_dynamic_groups_for_device;
DROP FUNCTION IF EXISTS evaluate_queued_dynamic_groups;
DROP FUNCTION IF EXISTS evaluate_dynamic_group;
DROP FUNCTION IF EXISTS resolve_inventory_field;
DROP FUNCTION IF EXISTS evaluate_dynamic_query_v2;
DROP FUNCTION IF EXISTS evaluate_condition_v2;
DROP FUNCTION IF EXISTS evaluate_dynamic_query;
DROP FUNCTION IF EXISTS evaluate_condition;
DROP FUNCTION IF EXISTS extract_label_key;

-- Drop extended projectors
DROP FUNCTION IF EXISTS reevaluate_compliance_policy_devices;
DROP FUNCTION IF EXISTS evaluate_device_compliance_policies;
DROP FUNCTION IF EXISTS recalculate_device_compliance;
DROP FUNCTION IF EXISTS project_server_settings_event;
DROP FUNCTION IF EXISTS project_luks_key_event;
DROP FUNCTION IF EXISTS project_lps_password_event;
DROP FUNCTION IF EXISTS project_compliance_policy_event;
DROP FUNCTION IF EXISTS project_compliance_event;
DROP FUNCTION IF EXISTS project_scim_group_mapping_event;
DROP FUNCTION IF EXISTS project_identity_provider_event;
DROP FUNCTION IF EXISTS project_user_group_event;
DROP FUNCTION IF EXISTS project_totp_event;
DROP FUNCTION IF EXISTS project_user_role_event;
DROP FUNCTION IF EXISTS project_role_event;

-- Drop core projectors
DROP FUNCTION IF EXISTS project_user_selection_event;
DROP FUNCTION IF EXISTS project_assignment_event;
DROP FUNCTION IF EXISTS project_device_group_event;
DROP FUNCTION IF EXISTS project_definition_event;
DROP FUNCTION IF EXISTS project_action_set_event;
DROP FUNCTION IF EXISTS project_execution_event;
DROP FUNCTION IF EXISTS project_action_event;
DROP FUNCTION IF EXISTS project_device_event;
DROP FUNCTION IF EXISTS project_token_event;
DROP FUNCTION IF EXISTS project_user_event;
DROP FUNCTION IF EXISTS generate_ulid;

-- Drop sequences
DROP SEQUENCE IF EXISTS linux_uid_seq;

-- Drop tables (reverse dependency order)
DROP TABLE IF EXISTS log_query_results;
DROP TABLE IF EXISTS device_assigned_groups_projection;
DROP TABLE IF EXISTS device_assigned_users_projection;
DROP TABLE IF EXISTS server_settings_projection;
DROP TABLE IF EXISTS compliance_policy_evaluation_projection;
DROP TABLE IF EXISTS compliance_policy_rules_projection;
DROP TABLE IF EXISTS compliance_policies_projection;
DROP TABLE IF EXISTS compliance_results_projection;
DROP TABLE IF EXISTS dynamic_user_group_evaluation_queue;
DROP TABLE IF EXISTS scim_group_mapping_projection;
DROP TABLE IF EXISTS auth_states;
DROP TABLE IF EXISTS identity_links_projection;
DROP TABLE IF EXISTS identity_providers_projection;
DROP TABLE IF EXISTS user_group_roles_projection;
DROP TABLE IF EXISTS user_group_members_projection;
DROP TABLE IF EXISTS user_groups_projection;
DROP TABLE IF EXISTS totp_projection;
DROP TABLE IF EXISTS user_roles_projection;
DROP TABLE IF EXISTS roles_projection;
DROP TABLE IF EXISTS device_inventory;
DROP TABLE IF EXISTS luks_tokens;
DROP TABLE IF EXISTS luks_keys_projection;
DROP TABLE IF EXISTS lps_passwords_projection;
DROP TABLE IF EXISTS projection_errors;
DROP TABLE IF EXISTS dynamic_group_evaluation_queue;
DROP TABLE IF EXISTS revoked_tokens;
DROP TABLE IF EXISTS user_selections_projection;
DROP TABLE IF EXISTS assignments_projection;
DROP TABLE IF EXISTS device_group_members_projection;
DROP TABLE IF EXISTS device_groups_projection;
DROP TABLE IF EXISTS definition_members_projection;
DROP TABLE IF EXISTS definitions_projection;
DROP TABLE IF EXISTS action_set_members_projection;
DROP TABLE IF EXISTS action_sets_projection;
DROP TABLE IF EXISTS executions_projection;
DROP TABLE IF EXISTS actions_projection;
DROP TABLE IF EXISTS devices_projection;
DROP TABLE IF EXISTS tokens_projection;
DROP TABLE IF EXISTS users_projection;
DROP TABLE IF EXISTS events;

-- Drop database roles
DROP ROLE IF EXISTS pm_indexer;
DROP ROLE IF EXISTS pm_readonly;

-- Drop extensions
DROP EXTENSION IF EXISTS pgcrypto;

-- +goose StatementEnd
