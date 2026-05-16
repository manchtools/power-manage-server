-- Seed data + PG roles previously scattered across migrations 001 / 004 /
-- 005. pg_dump --schema-only didn't capture these so they need to be
-- restored explicitly.
--
-- Wave H consolidation (tracker manchtools/power-manage-server#242):
-- everything in this file is replay-safe via ON CONFLICT / IF NOT
-- EXISTS so re-running the migration after a partial apply doesn't
-- corrupt seeded state.

-- +goose Up

-- ============================================================================
-- generate_ulid() utility — used by the "All Devices" seed below.
-- ============================================================================

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION generate_ulid() RETURNS text
    LANGUAGE plpgsql
    AS $$
DECLARE
    timestamp_ms BIGINT;
    random_bytes BYTEA;
    ulid TEXT := '';
    alphabet TEXT := '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
    i INTEGER;
    val BIGINT;
BEGIN
    timestamp_ms := (EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::BIGINT;

    FOR i IN REVERSE 9..0 LOOP
        ulid := ulid || substr(alphabet, (timestamp_ms % 32)::INTEGER + 1, 1);
        timestamp_ms := timestamp_ms / 32;
    END LOOP;

    ulid := reverse(ulid);

    random_bytes := gen_random_bytes(10);

    val := 0;
    FOR i IN 0..9 LOOP
        val := (val * 256) + get_byte(random_bytes, i);
        IF (i + 1) % 5 = 0 THEN
            FOR j IN REVERSE 7..0 LOOP
                ulid := ulid || substr(alphabet, ((val >> (j * 5)) & 31)::INTEGER + 1, 1);
            END LOOP;
            val := 0;
        END IF;
    END LOOP;

    RETURN ulid;
END;
$$;
-- +goose StatementEnd

-- ============================================================================
-- Server settings: the single 'global' row that handlers read on every
-- startup. The Go server-settings handler treats the row as guaranteed
-- to exist; missing it surfaces as a "no rows in result set" error.
-- ============================================================================

INSERT INTO server_settings_projection (id) VALUES ('global')
ON CONFLICT (id) DO NOTHING;

-- ============================================================================
-- System roles. The IDs are stable so the role reconciler on server
-- startup matches against them by primary key. Admin gets every
-- permission the app defines; User gets a curated subset.
-- ============================================================================

INSERT INTO roles_projection (id, name, description, permissions, is_system, created_at, updated_at, projection_version)
VALUES (
    '00000000000000000000000001', 'Admin', 'Full system access',
    '{GetCurrentUser,GetUser,GetUser:self,ListUsers,CreateUser,UpdateUserEmail,UpdateUserEmail:self,UpdateUserPassword,UpdateUserPassword:self,SetUserDisabled,UpdateUserProfile,UpdateUserProfile:self,DeleteUser,UpdateUserSshSettings,UpdateUserSshSettings:self,UpdateUserLinuxUsername,UpdateUserLinuxUsername:self,AddUserSshKey,AddUserSshKey:self,RemoveUserSshKey,RemoveUserSshKey:self,ListDevices,ListDevices:assigned,GetDevice,GetDevice:assigned,SetDeviceLabel,RemoveDeviceLabel,AssignDevice,UnassignDevice,ListDeviceAssignees,SetDeviceSyncInterval,TriggerAgentUpdate,DeleteDevice,CreateToken,CreateToken:self,GetToken,ListTokens,RenameToken,SetTokenDisabled,DeleteToken,CreateAction,GetAction,ListActions,RenameAction,UpdateActionDescription,UpdateActionParams,DeleteAction,CreateActionSet,GetActionSet,ListActionSets,RenameActionSet,UpdateActionSetDescription,DeleteActionSet,AddActionToSet,RemoveActionFromSet,ReorderActionInSet,CreateDefinition,GetDefinition,ListDefinitions,RenameDefinition,UpdateDefinitionDescription,DeleteDefinition,AddActionSetToDefinition,RemoveActionSetFromDefinition,ReorderActionSetInDefinition,CreateDeviceGroup,GetDeviceGroup,ListDeviceGroups,ListDeviceGroupsForDevice,RenameDeviceGroup,UpdateDeviceGroupDescription,UpdateDeviceGroupQuery,DeleteDeviceGroup,AddDeviceToGroup,RemoveDeviceFromGroup,ValidateDynamicQuery,EvaluateDynamicGroup,SetDeviceGroupSyncInterval,CreateAssignment,DeleteAssignment,ListAssignments,GetDeviceAssignments,GetUserAssignments,SetUserSelection,ListAvailableActions,DispatchAction,DispatchToMultiple,DispatchAssignedActions,DispatchActionSet,DispatchDefinition,DispatchToGroup,DispatchInstantAction,GetExecution,ListExecutions,DispatchOSQuery,GetOSQueryResult,GetDeviceInventory,RefreshDeviceInventory,QueryDeviceLogs,GetDeviceLogResult,GetDeviceCompliance,GetDeviceCompliance:assigned,CreateCompliancePolicy,GetCompliancePolicy,ListCompliancePolicies,RenameCompliancePolicy,UpdateCompliancePolicyDescription,DeleteCompliancePolicy,AddCompliancePolicyRule,RemoveCompliancePolicyRule,UpdateCompliancePolicyRule,GetDeviceCompliancePolicyStatus,GetDeviceCompliancePolicyStatus:assigned,ListAuditEvents,GetDeviceLpsPasswords,GetDeviceLuksKeys,CreateLuksToken,RevokeLuksDeviceKey,SetupTOTP,VerifyTOTP,DisableTOTP,AdminDisableUserTOTP,GetTOTPStatus,RegenerateBackupCodes,CreateRole,GetRole,ListRoles,UpdateRole,DeleteRole,AssignRoleToUser,RevokeRoleFromUser,ListPermissions,CreateUserGroup,GetUserGroup,ListUserGroups,UpdateUserGroup,DeleteUserGroup,AddUserToGroup,RemoveUserFromGroup,AssignRoleToUserGroup,RevokeRoleFromUserGroup,ListUserGroupsForUser,UpdateUserGroupQuery,ValidateUserGroupQuery,EvaluateDynamicUserGroup,CreateIdentityProvider,GetIdentityProvider,ListIdentityProviders,UpdateIdentityProvider,DeleteIdentityProvider,EnableSCIM,DisableSCIM,RotateSCIMToken,ListIdentityLinks,UnlinkIdentity,Search,RebuildSearchIndex,GetServerSettings,UpdateServerSettings,SetUserProvisioningEnabled}',
    TRUE, NOW(), NOW(), 0
)
ON CONFLICT (id) DO NOTHING;

INSERT INTO roles_projection (id, name, description, permissions, is_system, created_at, updated_at, projection_version)
VALUES (
    '00000000000000000000000002', 'User', 'Basic user access',
    '{GetCurrentUser,GetUser:self,UpdateUserEmail:self,UpdateUserPassword:self,UpdateUserProfile:self,UpdateUserSshSettings:self,UpdateUserLinuxUsername:self,SetupTOTP,VerifyTOTP,DisableTOTP,GetTOTPStatus,RegenerateBackupCodes,ListDevices:assigned,GetDevice:assigned,CreateToken:self,SetUserSelection,ListAvailableActions,ListIdentityLinks,UnlinkIdentity,GetDeviceCompliance:assigned,AddUserSshKey:self,RemoveUserSshKey:self}',
    TRUE, NOW(), NOW(), 0
)
ON CONFLICT (id) DO NOTHING;

-- ============================================================================
-- "All Devices" dynamic group. Emitted as a DeviceGroupCreated event so the
-- projector path takes over from here. Guarded by EXISTS so a re-run leaves
-- the existing group alone.
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
-- Database roles for the read-only / indexer login. The indexer service
-- uses pm_indexer; everything else uses the owning role.
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

-- +goose Down

-- Intentionally not reversible — see header on every consolidation
-- migration in this set.
SELECT 1;
