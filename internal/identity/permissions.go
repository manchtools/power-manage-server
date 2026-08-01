package identity

// The permission keys this package gates on. They are named constants
// rather than literals so a handler and the registry cannot drift on a
// typo — a misspelled literal would silently gate on a permission
// nobody holds, which reads as "closed" until someone widens a role to
// make it work.
//
// A guard test asserts every constant here is a registered permission.
const (
	PermGetCurrentUser = "GetCurrentUser"

	PermGetUser                    = "GetUser"
	PermListUsers                  = "ListUsers"
	PermCreateUser                 = "CreateUser"
	PermUpdateUserEmail            = "UpdateUserEmail"
	PermSetUserDisabled            = "SetUserDisabled"
	PermUpdateUserProfile          = "UpdateUserProfile"
	PermUpdateUserLinuxUsername    = "UpdateUserLinuxUsername"
	PermUpdateUserSshSettings      = "UpdateUserSshSettings"
	PermAddUserSshKey              = "AddUserSshKey"
	PermRemoveUserSshKey           = "RemoveUserSshKey"
	PermDeleteUser                 = "DeleteUser"
	PermSetUserProvisioningEnabled = "SetUserProvisioningEnabled"

	PermCreateRole         = "CreateRole"
	PermGetRole            = "GetRole"
	PermListRoles          = "ListRoles"
	PermUpdateRole         = "UpdateRole"
	PermDeleteRole         = "DeleteRole"
	PermAssignRoleToUser   = "AssignRoleToUser"
	PermRevokeRoleFromUser = "RevokeRoleFromUser"
	PermListPermissions    = "ListPermissions"

	PermAssignRoleToUserGroup   = "AssignRoleToUserGroup"
	PermRevokeRoleFromUserGroup = "RevokeRoleFromUserGroup"
	PermCreateStaticUserGroup   = "CreateStaticUserGroup"
	PermCreateDynamicUserGroup  = "CreateDynamicUserGroup"
	PermGetUserGroup            = "GetUserGroup"
	PermListUserGroups          = "ListUserGroups"
	PermUpdateUserGroup         = "UpdateUserGroup"
	PermDeleteUserGroup         = "DeleteUserGroup"
	PermAddUserToGroup          = "AddUserToGroup"
	PermRemoveUserFromGroup     = "RemoveUserFromGroup"
	PermListUserGroupsForUser   = "ListUserGroupsForUser"
	PermSetUserGroupMaintenance = "SetUserGroupMaintenanceWindow"

	PermCreateIdentityProvider = "CreateIdentityProvider"
	PermGetIdentityProvider    = "GetIdentityProvider"
	PermListIdentityProviders  = "ListIdentityProviders"
	PermUpdateIdentityProvider = "UpdateIdentityProvider"
	PermDeleteIdentityProvider = "DeleteIdentityProvider"
	PermEnableSCIM             = "EnableSCIM"
	PermDisableSCIM            = "DisableSCIM"
	PermRotateSCIMToken        = "RotateSCIMToken"

	PermListIdentityLinks = "ListIdentityLinks"
	PermUnlinkIdentity    = "UnlinkIdentity"
)

// gatedPermissions is every permission key this package gates on,
// enumerated so the guard test can check them all rather than the ones
// someone remembered to list.
var gatedPermissions = []string{
	PermGetCurrentUser,
	PermGetUser, PermListUsers, PermCreateUser, PermUpdateUserEmail,
	PermSetUserDisabled, PermUpdateUserProfile, PermUpdateUserLinuxUsername,
	PermUpdateUserSshSettings, PermAddUserSshKey, PermRemoveUserSshKey,
	PermDeleteUser, PermSetUserProvisioningEnabled,
	PermCreateRole, PermGetRole, PermListRoles, PermUpdateRole, PermDeleteRole,
	PermAssignRoleToUser, PermRevokeRoleFromUser, PermListPermissions,
	PermAssignRoleToUserGroup, PermRevokeRoleFromUserGroup,
	PermCreateStaticUserGroup, PermCreateDynamicUserGroup,
	PermGetUserGroup, PermListUserGroups, PermUpdateUserGroup, PermDeleteUserGroup,
	PermAddUserToGroup, PermRemoveUserFromGroup, PermListUserGroupsForUser,
	PermSetUserGroupMaintenance,
	PermCreateIdentityProvider, PermGetIdentityProvider, PermListIdentityProviders,
	PermUpdateIdentityProvider, PermDeleteIdentityProvider,
	PermEnableSCIM, PermDisableSCIM, PermRotateSCIMToken,
	PermListIdentityLinks, PermUnlinkIdentity,
}

// GatedPermissions returns every permission key this package gates on.
// A guard test uses it to assert each one is registered, so a typo
// cannot silently gate on a permission nobody can hold.
func GatedPermissions() []string {
	return append([]string(nil), gatedPermissions...)
}
