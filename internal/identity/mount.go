package identity

import (
	"net/http"

	"connectrpc.com/connect"

	"github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1/powermanagev1connect"
)

// Mount registers the identity procedures on mux.
//
// Each procedure is mounted at its own canonical Connect path with the
// shared interceptor chain, rather than through the whole-service
// constructor: the identity handlers are one part of the control
// service, and mounting only what this package implements keeps the
// wiring honest about which procedures are actually served.
//
// Procedures returns the exact set that was mounted, so a test can
// assert the surface rather than trusting this list.
func (h *Handlers) Mount(mux *http.ServeMux, opts ...connect.HandlerOption) []string {
	var mounted []string
	register := func(procedure string, handler http.Handler) {
		mux.Handle(procedure, handler)
		mounted = append(mounted, procedure)
	}
	// Sessions.
	register(powermanagev1connect.ControlServiceRefreshTokenProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceRefreshTokenProcedure, h.RefreshToken, opts...))
	register(powermanagev1connect.ControlServiceLogoutProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceLogoutProcedure, h.Logout, opts...))
	register(powermanagev1connect.ControlServiceGetCurrentUserProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceGetCurrentUserProcedure, h.GetCurrentUser, opts...))

	// Single sign-on.
	register(powermanagev1connect.ControlServiceListAuthMethodsProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceListAuthMethodsProcedure, h.ListAuthMethods, opts...))
	register(powermanagev1connect.ControlServiceGetSSOLoginURLProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceGetSSOLoginURLProcedure, h.GetSSOLoginURL, opts...))
	register(powermanagev1connect.ControlServiceSSOCallbackProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceSSOCallbackProcedure, h.SSOCallback, opts...))

	// Identity providers.
	register(powermanagev1connect.ControlServiceCreateIdentityProviderProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceCreateIdentityProviderProcedure, h.CreateIdentityProvider, opts...))
	register(powermanagev1connect.ControlServiceGetIdentityProviderProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceGetIdentityProviderProcedure, h.GetIdentityProvider, opts...))
	register(powermanagev1connect.ControlServiceListIdentityProvidersProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceListIdentityProvidersProcedure, h.ListIdentityProviders, opts...))
	register(powermanagev1connect.ControlServiceUpdateIdentityProviderProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceUpdateIdentityProviderProcedure, h.UpdateIdentityProvider, opts...))
	register(powermanagev1connect.ControlServiceDeleteIdentityProviderProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceDeleteIdentityProviderProcedure, h.DeleteIdentityProvider, opts...))
	register(powermanagev1connect.ControlServiceEnableSCIMProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceEnableSCIMProcedure, h.EnableSCIM, opts...))
	register(powermanagev1connect.ControlServiceDisableSCIMProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceDisableSCIMProcedure, h.DisableSCIM, opts...))
	register(powermanagev1connect.ControlServiceRotateSCIMTokenProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceRotateSCIMTokenProcedure, h.RotateSCIMToken, opts...))

	// Identity links.
	register(powermanagev1connect.ControlServiceListIdentityLinksProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceListIdentityLinksProcedure, h.ListIdentityLinks, opts...))
	register(powermanagev1connect.ControlServiceUnlinkIdentityProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceUnlinkIdentityProcedure, h.UnlinkIdentity, opts...))

	// Users.
	register(powermanagev1connect.ControlServiceCreateUserProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceCreateUserProcedure, h.CreateUser, opts...))
	register(powermanagev1connect.ControlServiceGetUserProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceGetUserProcedure, h.GetUser, opts...))
	register(powermanagev1connect.ControlServiceListUsersProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceListUsersProcedure, h.ListUsers, opts...))
	register(powermanagev1connect.ControlServiceUpdateUserEmailProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceUpdateUserEmailProcedure, h.UpdateUserEmail, opts...))
	register(powermanagev1connect.ControlServiceSetUserDisabledProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceSetUserDisabledProcedure, h.SetUserDisabled, opts...))
	register(powermanagev1connect.ControlServiceUpdateUserProfileProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceUpdateUserProfileProcedure, h.UpdateUserProfile, opts...))
	register(powermanagev1connect.ControlServiceUpdateUserLinuxUsernameProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceUpdateUserLinuxUsernameProcedure, h.UpdateUserLinuxUsername, opts...))
	register(powermanagev1connect.ControlServiceUpdateUserSshSettingsProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceUpdateUserSshSettingsProcedure, h.UpdateUserSshSettings, opts...))
	register(powermanagev1connect.ControlServiceAddUserSshKeyProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceAddUserSshKeyProcedure, h.AddUserSshKey, opts...))
	register(powermanagev1connect.ControlServiceRemoveUserSshKeyProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceRemoveUserSshKeyProcedure, h.RemoveUserSshKey, opts...))
	register(powermanagev1connect.ControlServiceSetUserProvisioningEnabledProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceSetUserProvisioningEnabledProcedure, h.SetUserProvisioningEnabled, opts...))
	register(powermanagev1connect.ControlServiceDeleteUserProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceDeleteUserProcedure, h.DeleteUser, opts...))

	// User groups and membership.
	register(powermanagev1connect.ControlServiceCreateUserGroupProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceCreateUserGroupProcedure, h.CreateUserGroup, opts...))
	register(powermanagev1connect.ControlServiceGetUserGroupProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceGetUserGroupProcedure, h.GetUserGroup, opts...))
	register(powermanagev1connect.ControlServiceListUserGroupsProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceListUserGroupsProcedure, h.ListUserGroups, opts...))
	register(powermanagev1connect.ControlServiceUpdateUserGroupProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceUpdateUserGroupProcedure, h.UpdateUserGroup, opts...))
	register(powermanagev1connect.ControlServiceDeleteUserGroupProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceDeleteUserGroupProcedure, h.DeleteUserGroup, opts...))
	register(powermanagev1connect.ControlServiceAddUserToGroupProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceAddUserToGroupProcedure, h.AddUserToGroup, opts...))
	register(powermanagev1connect.ControlServiceRemoveUserFromGroupProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceRemoveUserFromGroupProcedure, h.RemoveUserFromGroup, opts...))
	register(powermanagev1connect.ControlServiceListUserGroupsForUserProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceListUserGroupsForUserProcedure, h.ListUserGroupsForUser, opts...))
	register(powermanagev1connect.ControlServiceSetUserGroupMaintenanceWindowProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceSetUserGroupMaintenanceWindowProcedure, h.SetUserGroupMaintenanceWindow, opts...))
	register(powermanagev1connect.ControlServiceUpdateUserGroupQueryProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceUpdateUserGroupQueryProcedure, h.UpdateUserGroupQuery, opts...))
	register(powermanagev1connect.ControlServiceValidateUserGroupQueryProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceValidateUserGroupQueryProcedure, h.ValidateUserGroupQuery, opts...))
	register(powermanagev1connect.ControlServiceEvaluateDynamicUserGroupProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceEvaluateDynamicUserGroupProcedure, h.EvaluateDynamicUserGroup, opts...))

	// Roles and grants.
	register(powermanagev1connect.ControlServiceCreateRoleProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceCreateRoleProcedure, h.CreateRole, opts...))
	register(powermanagev1connect.ControlServiceGetRoleProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceGetRoleProcedure, h.GetRole, opts...))
	register(powermanagev1connect.ControlServiceListRolesProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceListRolesProcedure, h.ListRoles, opts...))
	register(powermanagev1connect.ControlServiceUpdateRoleProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceUpdateRoleProcedure, h.UpdateRole, opts...))
	register(powermanagev1connect.ControlServiceDeleteRoleProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceDeleteRoleProcedure, h.DeleteRole, opts...))
	register(powermanagev1connect.ControlServiceAssignRoleToUserProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceAssignRoleToUserProcedure, h.AssignRoleToUser, opts...))
	register(powermanagev1connect.ControlServiceRevokeRoleFromUserProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceRevokeRoleFromUserProcedure, h.RevokeRoleFromUser, opts...))
	register(powermanagev1connect.ControlServiceAssignRoleToUserGroupProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceAssignRoleToUserGroupProcedure, h.AssignRoleToUserGroup, opts...))
	register(powermanagev1connect.ControlServiceRevokeRoleFromUserGroupProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceRevokeRoleFromUserGroupProcedure, h.RevokeRoleFromUserGroup, opts...))
	register(powermanagev1connect.ControlServiceListPermissionsProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceListPermissionsProcedure, h.ListPermissions, opts...))

	// Fleet settings.
	register(powermanagev1connect.ControlServiceGetServerSettingsProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceGetServerSettingsProcedure, h.GetServerSettings, opts...))
	register(powermanagev1connect.ControlServiceUpdateServerSettingsProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceUpdateServerSettingsProcedure, h.UpdateServerSettings, opts...))

	return mounted
}

// MutationProcedures is the exact set of identity procedures that
// change state. It is what an audit-coverage test enumerates: every
// entry must be shown to write its operation and effects in the same
// transaction as its mutation, and an entry added to Mount without
// being classified here fails that test.
func MutationProcedures() []string {
	return []string{
		powermanagev1connect.ControlServiceRefreshTokenProcedure,
		powermanagev1connect.ControlServiceLogoutProcedure,
		powermanagev1connect.ControlServiceGetSSOLoginURLProcedure,
		powermanagev1connect.ControlServiceSSOCallbackProcedure,
		powermanagev1connect.ControlServiceCreateIdentityProviderProcedure,
		powermanagev1connect.ControlServiceUpdateIdentityProviderProcedure,
		powermanagev1connect.ControlServiceDeleteIdentityProviderProcedure,
		powermanagev1connect.ControlServiceEnableSCIMProcedure,
		powermanagev1connect.ControlServiceDisableSCIMProcedure,
		powermanagev1connect.ControlServiceRotateSCIMTokenProcedure,
		powermanagev1connect.ControlServiceUnlinkIdentityProcedure,
		powermanagev1connect.ControlServiceCreateUserProcedure,
		powermanagev1connect.ControlServiceUpdateUserEmailProcedure,
		powermanagev1connect.ControlServiceSetUserDisabledProcedure,
		powermanagev1connect.ControlServiceUpdateUserProfileProcedure,
		powermanagev1connect.ControlServiceUpdateUserLinuxUsernameProcedure,
		powermanagev1connect.ControlServiceUpdateUserSshSettingsProcedure,
		powermanagev1connect.ControlServiceAddUserSshKeyProcedure,
		powermanagev1connect.ControlServiceRemoveUserSshKeyProcedure,
		powermanagev1connect.ControlServiceSetUserProvisioningEnabledProcedure,
		powermanagev1connect.ControlServiceDeleteUserProcedure,
		powermanagev1connect.ControlServiceCreateUserGroupProcedure,
		powermanagev1connect.ControlServiceUpdateUserGroupProcedure,
		powermanagev1connect.ControlServiceDeleteUserGroupProcedure,
		powermanagev1connect.ControlServiceAddUserToGroupProcedure,
		powermanagev1connect.ControlServiceRemoveUserFromGroupProcedure,
		powermanagev1connect.ControlServiceSetUserGroupMaintenanceWindowProcedure,
		powermanagev1connect.ControlServiceUpdateUserGroupQueryProcedure,
		powermanagev1connect.ControlServiceEvaluateDynamicUserGroupProcedure,
		powermanagev1connect.ControlServiceCreateRoleProcedure,
		powermanagev1connect.ControlServiceUpdateRoleProcedure,
		powermanagev1connect.ControlServiceDeleteRoleProcedure,
		powermanagev1connect.ControlServiceAssignRoleToUserProcedure,
		powermanagev1connect.ControlServiceRevokeRoleFromUserProcedure,
		powermanagev1connect.ControlServiceAssignRoleToUserGroupProcedure,
		powermanagev1connect.ControlServiceRevokeRoleFromUserGroupProcedure,
		powermanagev1connect.ControlServiceUpdateServerSettingsProcedure,
	}
}

// ReadProcedures is the exact set of identity procedures that change
// nothing.
func ReadProcedures() []string {
	return []string{
		powermanagev1connect.ControlServiceGetCurrentUserProcedure,
		powermanagev1connect.ControlServiceListAuthMethodsProcedure,
		powermanagev1connect.ControlServiceGetIdentityProviderProcedure,
		powermanagev1connect.ControlServiceListIdentityProvidersProcedure,
		powermanagev1connect.ControlServiceListIdentityLinksProcedure,
		powermanagev1connect.ControlServiceGetUserProcedure,
		powermanagev1connect.ControlServiceListUsersProcedure,
		powermanagev1connect.ControlServiceGetUserGroupProcedure,
		powermanagev1connect.ControlServiceListUserGroupsProcedure,
		powermanagev1connect.ControlServiceListUserGroupsForUserProcedure,
		powermanagev1connect.ControlServiceValidateUserGroupQueryProcedure,
		powermanagev1connect.ControlServiceGetRoleProcedure,
		powermanagev1connect.ControlServiceListRolesProcedure,
		powermanagev1connect.ControlServiceListPermissionsProcedure,
		powermanagev1connect.ControlServiceGetServerSettingsProcedure,
	}
}
