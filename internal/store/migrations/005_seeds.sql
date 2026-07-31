-- Rows the server assumes exist on first boot.
--
-- The singleton server-settings row and the two system roles. Their
-- ids are stable so the role reconciler matches them by primary key.
--
-- Permission arrays are the initial snapshot only: the reconciler
-- refreshes them from the code registry on every boot. Timestamps are
-- fixed literals so a fresh install is byte-identical across machines.

-- +goose Up

INSERT INTO public.server_settings (id, updated_at)
VALUES ('global', '2026-01-01 00:00:00+00')
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.roles (id, name, description, permissions, is_system, created_at, updated_at)
VALUES (
    '00000000000000000000000001', 'Admin', 'Full system access',
    '{GetCurrentUser,GetUser,GetUser:self,ListUsers,CreateUser,UpdateUserEmail,UpdateUserEmail:self,SetUserDisabled,UpdateUserProfile,UpdateUserProfile:self,DeleteUser,UpdateUserSshSettings,UpdateUserSshSettings:self,UpdateUserLinuxUsername,UpdateUserLinuxUsername:self,AddUserSshKey,AddUserSshKey:self,RemoveUserSshKey,RemoveUserSshKey:self,ListDevices,ListDevices:assigned,GetDevice,GetDevice:assigned,SetDeviceLabel,RemoveDeviceLabel,AssignDevice,UnassignDevice,ListDeviceAssignees,SetDeviceSyncInterval,TriggerAgentUpdate,DeleteDevice,CreateToken,CreateToken:self,GetToken,ListTokens,RenameToken,SetTokenDisabled,DeleteToken,CreateAction,GetAction,ListActions,RenameAction,UpdateActionDescription,UpdateActionParams,DeleteAction,CreateActionSet,GetActionSet,ListActionSets,RenameActionSet,UpdateActionSetDescription,DeleteActionSet,AddActionToSet,RemoveActionFromSet,ReorderActionInSet,CreateDefinition,GetDefinition,ListDefinitions,RenameDefinition,UpdateDefinitionDescription,DeleteDefinition,AddActionSetToDefinition,RemoveActionSetFromDefinition,ReorderActionSetInDefinition,CreateDeviceGroup,GetDeviceGroup,ListDeviceGroups,ListDeviceGroupsForDevice,RenameDeviceGroup,UpdateDeviceGroupDescription,UpdateDeviceGroupQuery,DeleteDeviceGroup,AddDeviceToGroup,RemoveDeviceFromGroup,ValidateDynamicQuery,EvaluateDynamicGroup,SetDeviceGroupSyncInterval,CreateAssignment,DeleteAssignment,ListAssignments,GetDeviceAssignments,GetUserAssignments,SetUserSelection,ListAvailableActions,DispatchAction,DispatchToMultiple,DispatchAssignedActions,DispatchActionSet,DispatchDefinition,DispatchToGroup,DispatchInstantAction,GetExecution,ListExecutions,DispatchOSQuery,GetOSQueryResult,GetDeviceInventory,RefreshDeviceInventory,QueryDeviceLogs,GetDeviceLogResult,GetDeviceCompliance,GetDeviceCompliance:assigned,CreateCompliancePolicy,GetCompliancePolicy,ListCompliancePolicies,RenameCompliancePolicy,UpdateCompliancePolicyDescription,DeleteCompliancePolicy,AddCompliancePolicyRule,RemoveCompliancePolicyRule,UpdateCompliancePolicyRule,GetDeviceCompliancePolicyStatus,GetDeviceCompliancePolicyStatus:assigned,ListAuditEvents,GetDeviceLpsPasswords,GetDeviceLuksKeys,CreateLuksToken,RevokeLuksDeviceKey,CreateRole,GetRole,ListRoles,UpdateRole,DeleteRole,AssignRoleToUser,RevokeRoleFromUser,ListPermissions,CreateUserGroup,GetUserGroup,ListUserGroups,UpdateUserGroup,DeleteUserGroup,AddUserToGroup,RemoveUserFromGroup,AssignRoleToUserGroup,RevokeRoleFromUserGroup,ListUserGroupsForUser,UpdateUserGroupQuery,ValidateUserGroupQuery,EvaluateDynamicUserGroup,CreateIdentityProvider,GetIdentityProvider,ListIdentityProviders,UpdateIdentityProvider,DeleteIdentityProvider,EnableSCIM,DisableSCIM,RotateSCIMToken,ListIdentityLinks,UnlinkIdentity,Search,RebuildSearchIndex,GetServerSettings,UpdateServerSettings,SetUserProvisioningEnabled}',
    TRUE, '2026-01-01 00:00:00+00', '2026-01-01 00:00:00+00'
)
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.roles (id, name, description, permissions, is_system, created_at, updated_at)
VALUES (
    '00000000000000000000000002', 'User', 'Basic user access',
    '{GetCurrentUser,GetUser:self,UpdateUserEmail:self,UpdateUserProfile:self,UpdateUserSshSettings:self,ListDevices:assigned,GetDevice:assigned,CreateToken:self,SetUserSelection,ListAvailableActions,ListIdentityLinks,UnlinkIdentity,GetDeviceCompliance:assigned,AddUserSshKey:self,RemoveUserSshKey:self,StopTerminal}',
    TRUE, '2026-01-01 00:00:00+00', '2026-01-01 00:00:00+00'
)
ON CONFLICT (id) DO NOTHING;

-- +goose Down

SELECT 1;
