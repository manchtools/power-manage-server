-- +goose Up

-- ============================================================================
-- SYNC SYSTEM ROLE PERMISSIONS
-- ============================================================================
-- Bring Admin and User system roles up to date with all permissions defined
-- in auth/permissions.go. This replaces the full permissions array rather than
-- appending individual items, ensuring a clean, idempotent result.

-- Admin: all base (unrestricted) permissions
UPDATE roles_projection
SET permissions = '{GetCurrentUser,GetUser,ListUsers,CreateUser,UpdateUserEmail,UpdateUserPassword,SetUserDisabled,UpdateUserProfile,DeleteUser,UpdateUserSshSettings,AddUserSshKey,RemoveUserSshKey,ListDevices,GetDevice,SetDeviceLabel,RemoveDeviceLabel,AssignDevice,UnassignDevice,SetDeviceSyncInterval,DeleteDevice,CreateToken,GetToken,ListTokens,RenameToken,SetTokenDisabled,DeleteToken,CreateAction,GetAction,ListActions,RenameAction,UpdateActionDescription,UpdateActionParams,DeleteAction,CreateActionSet,GetActionSet,ListActionSets,RenameActionSet,UpdateActionSetDescription,DeleteActionSet,AddActionToSet,RemoveActionFromSet,ReorderActionInSet,CreateDefinition,GetDefinition,ListDefinitions,RenameDefinition,UpdateDefinitionDescription,DeleteDefinition,AddActionSetToDefinition,RemoveActionSetFromDefinition,ReorderActionSetInDefinition,CreateDeviceGroup,GetDeviceGroup,ListDeviceGroups,RenameDeviceGroup,UpdateDeviceGroupDescription,UpdateDeviceGroupQuery,DeleteDeviceGroup,AddDeviceToGroup,RemoveDeviceFromGroup,ValidateDynamicQuery,EvaluateDynamicGroup,SetDeviceGroupSyncInterval,CreateAssignment,DeleteAssignment,ListAssignments,GetDeviceAssignments,GetUserAssignments,SetUserSelection,ListAvailableActions,DispatchAction,DispatchToMultiple,DispatchAssignedActions,DispatchActionSet,DispatchDefinition,DispatchToGroup,DispatchInstantAction,GetExecution,ListExecutions,DispatchOSQuery,GetOSQueryResult,GetDeviceInventory,RefreshDeviceInventory,GetDeviceCompliance,CreateCompliancePolicy,GetCompliancePolicy,ListCompliancePolicies,RenameCompliancePolicy,UpdateCompliancePolicyDescription,DeleteCompliancePolicy,AddCompliancePolicyRule,RemoveCompliancePolicyRule,UpdateCompliancePolicyRule,GetDeviceCompliancePolicyStatus,ListAuditEvents,GetDeviceLpsPasswords,GetDeviceLuksKeys,CreateLuksToken,RevokeLuksDeviceKey,SetupTOTP,VerifyTOTP,DisableTOTP,AdminDisableUserTOTP,GetTOTPStatus,RegenerateBackupCodes,CreateRole,GetRole,ListRoles,UpdateRole,DeleteRole,AssignRoleToUser,RevokeRoleFromUser,ListPermissions,CreateUserGroup,GetUserGroup,ListUserGroups,UpdateUserGroup,DeleteUserGroup,AddUserToGroup,RemoveUserFromGroup,AssignRoleToUserGroup,RevokeRoleFromUserGroup,ListUserGroupsForUser,UpdateUserGroupQuery,ValidateUserGroupQuery,EvaluateDynamicUserGroup,CreateIdentityProvider,GetIdentityProvider,ListIdentityProviders,UpdateIdentityProvider,DeleteIdentityProvider,EnableSCIM,DisableSCIM,RotateSCIMToken,ListIdentityLinks,UnlinkIdentity,Search,RebuildSearchIndex,GetServerSettings,UpdateServerSettings,SetUserProvisioningEnabled}',
    updated_at = now()
WHERE name = 'Admin' AND is_system = TRUE;

-- User: self-service permissions (matching DefaultUserPermissions in auth/permissions.go)
UPDATE roles_projection
SET permissions = '{GetCurrentUser,GetUser:self,UpdateUserEmail:self,UpdateUserPassword:self,UpdateUserProfile:self,SetupTOTP,VerifyTOTP,DisableTOTP,GetTOTPStatus,RegenerateBackupCodes,ListDevices:assigned,GetDevice:assigned,CreateToken:self,SetUserSelection,ListAvailableActions,ListIdentityLinks,UnlinkIdentity,GetDeviceCompliance:assigned,AddUserSshKey:self,RemoveUserSshKey:self}',
    updated_at = now()
WHERE name = 'User' AND is_system = TRUE;

-- ============================================================================
-- PRESEED "ALL DEVICES" DYNAMIC DEVICE GROUP
-- ============================================================================
-- Creates a dynamic group with an empty query that matches all devices.
-- Only created if no group named "All Devices" exists yet.

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

-- +goose Down

-- Restore original Admin permissions from migration 007
UPDATE roles_projection
SET permissions = '{GetCurrentUser,GetUser,ListUsers,CreateUser,UpdateUserEmail,UpdateUserPassword,SetUserDisabled,DeleteUser,ListDevices,GetDevice,SetDeviceLabel,RemoveDeviceLabel,AssignDevice,UnassignDevice,SetDeviceSyncInterval,DeleteDevice,CreateToken,GetToken,ListTokens,RenameToken,SetTokenDisabled,DeleteToken,CreateAction,GetAction,ListActions,RenameAction,UpdateActionDescription,UpdateActionParams,DeleteAction,CreateActionSet,GetActionSet,ListActionSets,RenameActionSet,UpdateActionSetDescription,DeleteActionSet,AddActionToSet,RemoveActionFromSet,ReorderActionInSet,CreateDefinition,GetDefinition,ListDefinitions,RenameDefinition,UpdateDefinitionDescription,DeleteDefinition,AddActionSetToDefinition,RemoveActionSetFromDefinition,ReorderActionSetInDefinition,CreateDeviceGroup,GetDeviceGroup,ListDeviceGroups,RenameDeviceGroup,UpdateDeviceGroupDescription,UpdateDeviceGroupQuery,DeleteDeviceGroup,AddDeviceToGroup,RemoveDeviceFromGroup,ValidateDynamicQuery,EvaluateDynamicGroup,SetDeviceGroupSyncInterval,CreateAssignment,DeleteAssignment,ListAssignments,GetDeviceAssignments,SetUserSelection,ListAvailableActions,DispatchAction,DispatchToMultiple,DispatchAssignedActions,DispatchActionSet,DispatchDefinition,DispatchToGroup,DispatchInstantAction,GetExecution,ListExecutions,ListAuditEvents,GetDeviceLpsPasswords,GetDeviceLuksKeys,CreateLuksToken,RevokeLuksDeviceKey,DispatchOSQuery,GetOSQueryResult,GetDeviceInventory,RefreshDeviceInventory,CreateRole,GetRole,ListRoles,UpdateRole,DeleteRole,AssignRoleToUser,RevokeRoleFromUser,ListPermissions}',
    updated_at = now()
WHERE name = 'Admin' AND is_system = TRUE;

-- Restore User permissions from migration 008 (with CreateToken:self)
UPDATE roles_projection
SET permissions = '{GetCurrentUser,GetUser:self,UpdateUserEmail:self,UpdateUserPassword:self,ListDevices:assigned,GetDevice:assigned,CreateToken:self,SetUserSelection,ListAvailableActions}',
    updated_at = now()
WHERE name = 'User' AND is_system = TRUE;

-- Remove the preseeded All Devices group
DELETE FROM events WHERE stream_type = 'device_group' AND event_type = 'DeviceGroupCreated' AND actor_id = 'migration' AND data->>'name' = 'All Devices';
DELETE FROM device_groups_projection WHERE name = 'All Devices' AND created_by = 'migration';
