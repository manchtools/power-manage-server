package auth

// PermissionTargetKind classifies the target kind a permission acts
// on, which determines whether (and how) it can be scoped on a role
// grant (manchtools/power-manage-server#7).
//
// Fail-closed semantic: a permission that does not explicitly
// declare a target kind stays at the zero value (TargetUnspecified)
// and is NOT scopable. Granting it with any scope_kind is rejected
// by the role-assignment handler. New permissions added without an
// explicit kind silently land at the safe default — the inverse
// (default-scopable) is the classic stale-allowlist failure mode.
//
// Use TargetDevice / TargetUser only when the permission's
// authorization decision can be expressed as "scope-id matches a
// group containing this device/user". Org-tier permissions
// (CreateRole, server settings, IDP/SCIM, audit) and permissions
// that can perturb other actors' scopes (dynamic-group ops, labels)
// stay TargetUnspecified.
type PermissionTargetKind int

const (
	// TargetUnspecified — not scopable. The zero value is the safe
	// default for any permission that hasn't been explicitly
	// classified.
	TargetUnspecified PermissionTargetKind = iota
	// TargetDevice — scopable with
	// RoleGrantScopeKind=DEVICE_GROUP only.
	TargetDevice
	// TargetUser — scopable with
	// RoleGrantScopeKind=USER_GROUP only.
	TargetUser
)

// PermissionInfo describes a single permission.
type PermissionInfo struct {
	Key         string // e.g. "CreateAction", "GetUser:self"
	Group       string // UI group: "Users", "Devices", etc.
	Description string
	// TargetKind classifies what kind of target this permission
	// acts on, used by the role-assignment handler to gate scoped
	// grants. TargetUnspecified (zero value) means the permission
	// is not scopable. server #7.
	TargetKind PermissionTargetKind
}

// AllPermissions returns every available permission with metadata.
func AllPermissions() []PermissionInfo {
	return []PermissionInfo{
		// Users
		{"GetCurrentUser", "Users", "View own profile", TargetUnspecified},
		{"GetUser", "Users", "View any user", TargetUser},
		{"GetUser:self", "Users", "View own profile only", TargetUnspecified},
		{"ListUsers", "Users", "List all users", TargetUser},
		{"CreateUser", "Users", "Create users", TargetUnspecified},
		{"UpdateUserEmail", "Users", "Change any user's email", TargetUser},
		{"UpdateUserEmail:self", "Users", "Change own email", TargetUnspecified},
		{"UpdateUserPassword", "Users", "Change any user's password", TargetUser},
		{"UpdateUserPassword:self", "Users", "Change own password", TargetUnspecified},
		{"SetUserDisabled", "Users", "Disable/enable users", TargetUser},
		{"UpdateUserProfile", "Users", "Update any user's profile", TargetUser},
		{"UpdateUserProfile:self", "Users", "Update own profile", TargetUnspecified},
		{"DeleteUser", "Users", "Delete users", TargetUser},
		{"UpdateUserSshSettings", "Users", "Update any user's SSH settings", TargetUser},
		{"UpdateUserSshSettings:self", "Users", "Update own SSH settings", TargetUnspecified},
		{"UpdateUserLinuxUsername", "Users", "Change any user's linux username", TargetUser},
		{"UpdateUserLinuxUsername:self", "Users", "Change own linux username", TargetUnspecified},
		{"AddUserSshKey", "Users", "Add SSH key to any user", TargetUser},
		{"AddUserSshKey:self", "Users", "Add own SSH key", TargetUnspecified},
		{"RemoveUserSshKey", "Users", "Remove SSH key from any user", TargetUser},
		{"RemoveUserSshKey:self", "Users", "Remove own SSH key", TargetUnspecified},
		// Devices
		{"ListDevices", "Devices", "List all devices", TargetDevice},
		{"ListDevices:assigned", "Devices", "List own assigned devices", TargetUnspecified},
		{"GetDevice", "Devices", "View any device", TargetDevice},
		{"GetDevice:assigned", "Devices", "View own assigned devices", TargetUnspecified},
		// SetDeviceLabel / RemoveDeviceLabel are intentionally NOT
		// scopable: labels feed dynamic device-group queries, so
		// scoping the labels permission would let a scope-confined
		// admin perturb OTHER admins' dynamic-group scopes. T-S2.
		{"SetDeviceLabel", "Devices", "Set device labels", TargetUnspecified},
		{"RemoveDeviceLabel", "Devices", "Remove device labels", TargetUnspecified},
		// AssignDevice / UnassignDevice manage the device-user
		// relationship; scoping them creates cross-kind semantics
		// that V1 explicitly excludes per kinds-don't-mix. Org-tier
		// for V1.
		{"AssignDevice", "Devices", "Assign devices to users or groups", TargetUnspecified},
		{"UnassignDevice", "Devices", "Unassign devices from users or groups", TargetUnspecified},
		{"ListDeviceAssignees", "Devices", "List device assignees", TargetUnspecified},
		{"SetDeviceSyncInterval", "Devices", "Set device sync interval", TargetDevice},
		{"DeleteDevice", "Devices", "Delete devices", TargetDevice},
		// Tokens
		{"CreateToken", "Tokens", "Create registration tokens", TargetUnspecified},
		{"CreateToken:self", "Tokens", "Create one-time token for self", TargetUnspecified},
		{"GetToken", "Tokens", "View tokens", TargetUnspecified},
		{"ListTokens", "Tokens", "List tokens", TargetUnspecified},
		{"RenameToken", "Tokens", "Rename tokens", TargetUnspecified},
		{"SetTokenDisabled", "Tokens", "Disable/enable tokens", TargetUnspecified},
		{"DeleteToken", "Tokens", "Delete tokens", TargetUnspecified},
		// Actions — org-tier objects (authored once, dispatched
		// per-device); scoping happens on the dispatch RPCs, not
		// the action CRUD.
		{"CreateAction", "Actions", "Create actions", TargetUnspecified},
		{"GetAction", "Actions", "View actions", TargetUnspecified},
		{"ListActions", "Actions", "List actions", TargetUnspecified},
		{"RenameAction", "Actions", "Rename actions", TargetUnspecified},
		{"UpdateActionDescription", "Actions", "Update action descriptions", TargetUnspecified},
		{"UpdateActionParams", "Actions", "Update action parameters", TargetUnspecified},
		{"DeleteAction", "Actions", "Delete actions", TargetUnspecified},
		// Action Sets — org-tier objects
		{"CreateActionSet", "Action Sets", "Create action sets", TargetUnspecified},
		{"GetActionSet", "Action Sets", "View action sets", TargetUnspecified},
		{"ListActionSets", "Action Sets", "List action sets", TargetUnspecified},
		{"RenameActionSet", "Action Sets", "Rename action sets", TargetUnspecified},
		{"UpdateActionSetDescription", "Action Sets", "Update action set descriptions", TargetUnspecified},
		{"UpdateActionSetSchedule", "Action Sets", "Update action set schedule", TargetUnspecified},
		{"DeleteActionSet", "Action Sets", "Delete action sets", TargetUnspecified},
		{"AddActionToSet", "Action Sets", "Add actions to sets", TargetUnspecified},
		{"RemoveActionFromSet", "Action Sets", "Remove actions from sets", TargetUnspecified},
		{"ReorderActionInSet", "Action Sets", "Reorder actions in sets", TargetUnspecified},
		// Definitions — org-tier objects
		{"CreateDefinition", "Definitions", "Create definitions", TargetUnspecified},
		{"GetDefinition", "Definitions", "View definitions", TargetUnspecified},
		{"ListDefinitions", "Definitions", "List definitions", TargetUnspecified},
		{"RenameDefinition", "Definitions", "Rename definitions", TargetUnspecified},
		{"UpdateDefinitionDescription", "Definitions", "Update definition descriptions", TargetUnspecified},
		{"UpdateDefinitionSchedule", "Definitions", "Update definition schedule", TargetUnspecified},
		{"DeleteDefinition", "Definitions", "Delete definitions", TargetUnspecified},
		{"AddActionSetToDefinition", "Definitions", "Add action sets to definitions", TargetUnspecified},
		{"RemoveActionSetFromDefinition", "Definitions", "Remove action sets from definitions", TargetUnspecified},
		{"ReorderActionSetInDefinition", "Definitions", "Reorder action sets in definitions", TargetUnspecified},
		// Device Groups
		//
		// CreateDeviceGroup was split into a static and a dynamic
		// variant in server #7. Static-group creation is safe to
		// scope (the scoped admin can only organize devices already
		// within their scope into sub-groups). Dynamic-group
		// creation stays unscopable because the query language
		// matches arbitrary device sets and could perturb other
		// actors' scopes — see T-S2 in the #7 design.
		{"CreateStaticDeviceGroup", "Device Groups", "Create static device groups", TargetDevice},
		{"CreateDynamicDeviceGroup", "Device Groups", "Create dynamic device groups", TargetUnspecified},
		{"GetDeviceGroup", "Device Groups", "View device groups", TargetDevice},
		{"ListDeviceGroups", "Device Groups", "List device groups", TargetDevice},
		{"ListDeviceGroupsForDevice", "Device Groups", "List device groups for a device", TargetDevice},
		{"RenameDeviceGroup", "Device Groups", "Rename device groups", TargetDevice},
		{"UpdateDeviceGroupDescription", "Device Groups", "Update device group descriptions", TargetDevice},
		{"UpdateDynamicDeviceGroupQuery", "Device Groups", "Update dynamic device group queries", TargetUnspecified},
		{"DeleteDeviceGroup", "Device Groups", "Delete device groups", TargetDevice},
		{"AddDeviceToGroup", "Device Groups", "Add devices to groups", TargetDevice},
		{"RemoveDeviceFromGroup", "Device Groups", "Remove devices from groups", TargetDevice},
		{"ValidateDynamicQuery", "Device Groups", "Validate dynamic queries", TargetUnspecified},
		{"EvaluateDynamicGroup", "Device Groups", "Evaluate dynamic groups", TargetUnspecified},
		{"SetDeviceGroupSyncInterval", "Device Groups", "Set device group sync interval", TargetDevice},
		{"SetDeviceGroupMaintenanceWindow", "Device Groups", "Set device group maintenance window", TargetDevice},
		// Assignments
		{"CreateAssignment", "Assignments", "Create assignments", TargetUnspecified},
		{"DeleteAssignment", "Assignments", "Delete assignments", TargetUnspecified},
		{"ListAssignments", "Assignments", "List assignments", TargetUnspecified},
		{"GetDeviceAssignments", "Assignments", "View device assignments", TargetUnspecified},
		{"GetUserAssignments", "Assignments", "View user assignments", TargetUnspecified},
		// User Selections
		{"SetUserSelection", "User Selections", "Manage user selections", TargetUnspecified},
		{"ListAvailableActions", "User Selections", "List available actions", TargetUnspecified},
		// Dispatch
		{"DispatchAction", "Dispatch", "Dispatch single action", TargetDevice},
		{"DispatchToMultiple", "Dispatch", "Dispatch to multiple devices", TargetDevice},
		{"DispatchAssignedActions", "Dispatch", "Sync assigned actions to device", TargetDevice},
		{"DispatchActionSet", "Dispatch", "Dispatch action set", TargetDevice},
		{"DispatchDefinition", "Dispatch", "Dispatch definition", TargetDevice},
		{"DispatchToGroup", "Dispatch", "Dispatch to device group", TargetDevice},
		{"DispatchInstantAction", "Dispatch", "Dispatch instant action", TargetDevice},
		// Executions
		{"GetExecution", "Executions", "View executions", TargetDevice},
		{"ListExecutions", "Executions", "List executions", TargetDevice},
		{"CancelExecution", "Executions", "Cancel pending executions", TargetDevice},
		// OSQuery
		{"DispatchOSQuery", "OSQuery", "Run OSQuery on device", TargetDevice},
		{"GetOSQueryResult", "OSQuery", "View OSQuery results", TargetDevice},
		{"GetDeviceInventory", "OSQuery", "View device inventory", TargetDevice},
		{"RefreshDeviceInventory", "OSQuery", "Refresh device inventory", TargetDevice},
		// Device Logs
		{"QueryDeviceLogs", "Device Logs", "Query device logs", TargetDevice},
		{"GetDeviceLogResult", "Device Logs", "View device log results", TargetDevice},
		// Compliance
		{"GetDeviceCompliance", "Compliance", "View device compliance", TargetDevice},
		{"GetDeviceCompliance:assigned", "Compliance", "View compliance for assigned devices", TargetUnspecified},
		// Compliance Policies — org-tier
		{"CreateCompliancePolicy", "Compliance Policies", "Create compliance policies", TargetUnspecified},
		{"GetCompliancePolicy", "Compliance Policies", "View compliance policies", TargetUnspecified},
		{"ListCompliancePolicies", "Compliance Policies", "List compliance policies", TargetUnspecified},
		{"RenameCompliancePolicy", "Compliance Policies", "Rename compliance policies", TargetUnspecified},
		{"UpdateCompliancePolicyDescription", "Compliance Policies", "Update compliance policy descriptions", TargetUnspecified},
		{"DeleteCompliancePolicy", "Compliance Policies", "Delete compliance policies", TargetUnspecified},
		{"AddCompliancePolicyRule", "Compliance Policies", "Add rules to compliance policies", TargetUnspecified},
		{"RemoveCompliancePolicyRule", "Compliance Policies", "Remove rules from compliance policies", TargetUnspecified},
		{"UpdateCompliancePolicyRule", "Compliance Policies", "Update compliance policy rules", TargetUnspecified},
		{"GetDeviceCompliancePolicyStatus", "Compliance Policies", "View device compliance policy status", TargetDevice},
		{"GetDeviceCompliancePolicyStatus:assigned", "Compliance Policies", "View compliance policy status for assigned devices", TargetUnspecified},
		// Audit — org-tier (V2 may revisit)
		{"ListAuditEvents", "Audit", "View audit log", TargetUnspecified},
		// LPS — security-sensitive, org-tier
		{"GetDeviceLpsPasswords", "LPS", "View LPS passwords", TargetUnspecified},
		// LUKS — security-sensitive, org-tier
		{"GetDeviceLuksKeys", "LUKS", "View LUKS keys", TargetUnspecified},
		{"CreateLuksToken", "LUKS", "Create LUKS recovery token", TargetUnspecified},
		{"RevokeLuksDeviceKey", "LUKS", "Revoke LUKS device key", TargetUnspecified},
		// TOTP
		{"SetupTOTP", "Authentication", "Set up TOTP 2FA", TargetUnspecified},
		{"VerifyTOTP", "Authentication", "Verify TOTP setup", TargetUnspecified},
		{"DisableTOTP", "Authentication", "Disable TOTP 2FA", TargetUnspecified},
		{"AdminDisableUserTOTP", "Users", "Disable TOTP for any user", TargetUser},
		{"GetTOTPStatus", "Authentication", "View TOTP status", TargetUnspecified},
		{"RegenerateBackupCodes", "Authentication", "Regenerate backup codes", TargetUnspecified},
		// Roles — org-tier. AssignRoleScope grants the authority to
		// attach a scope to a role grant (paired-or-neither
		// scope_kind+scope_id). server #7.
		{"CreateRole", "Roles", "Create roles", TargetUnspecified},
		{"GetRole", "Roles", "View roles", TargetUnspecified},
		{"ListRoles", "Roles", "List roles", TargetUnspecified},
		{"UpdateRole", "Roles", "Update roles", TargetUnspecified},
		{"DeleteRole", "Roles", "Delete roles", TargetUnspecified},
		{"AssignRoleToUser", "Roles", "Assign roles to users", TargetUnspecified},
		{"RevokeRoleFromUser", "Roles", "Revoke roles from users", TargetUnspecified},
		{"AssignRoleScope", "Roles", "Attach a scope (device group / user group) to a role grant", TargetUnspecified},
		{"ListPermissions", "Roles", "List available permissions", TargetUnspecified},
		// User Groups
		//
		// CreateUserGroup split into static + dynamic variants in
		// server #7, same rationale as CreateDeviceGroup. T-S2.
		{"CreateStaticUserGroup", "User Groups", "Create static user groups", TargetUser},
		{"CreateDynamicUserGroup", "User Groups", "Create dynamic user groups", TargetUnspecified},
		{"GetUserGroup", "User Groups", "View user groups", TargetUser},
		{"ListUserGroups", "User Groups", "List user groups", TargetUser},
		{"UpdateUserGroup", "User Groups", "Update user groups", TargetUser},
		{"DeleteUserGroup", "User Groups", "Delete user groups", TargetUser},
		{"AddUserToGroup", "User Groups", "Add users to groups", TargetUser},
		{"RemoveUserFromGroup", "User Groups", "Remove users from groups", TargetUser},
		{"AssignRoleToUserGroup", "User Groups", "Assign roles to user groups", TargetUnspecified},
		{"RevokeRoleFromUserGroup", "User Groups", "Revoke roles from user groups", TargetUnspecified},
		{"ListUserGroupsForUser", "User Groups", "List user groups for a user", TargetUser},
		{"UpdateDynamicUserGroupQuery", "User Groups", "Update dynamic user group queries", TargetUnspecified},
		{"ValidateUserGroupQuery", "User Groups", "Validate user group queries", TargetUnspecified},
		{"EvaluateDynamicUserGroup", "User Groups", "Evaluate dynamic user groups", TargetUnspecified},
		{"SetUserGroupMaintenanceWindow", "User Groups", "Set user group maintenance window", TargetUser},
		// Identity Providers — org-tier
		{"CreateIdentityProvider", "Identity Providers", "Create identity providers", TargetUnspecified},
		{"GetIdentityProvider", "Identity Providers", "View identity providers", TargetUnspecified},
		{"ListIdentityProviders", "Identity Providers", "List identity providers", TargetUnspecified},
		{"UpdateIdentityProvider", "Identity Providers", "Update identity providers", TargetUnspecified},
		{"DeleteIdentityProvider", "Identity Providers", "Delete identity providers", TargetUnspecified},
		{"EnableSCIM", "Identity Providers", "Enable SCIM provisioning", TargetUnspecified},
		{"DisableSCIM", "Identity Providers", "Disable SCIM provisioning", TargetUnspecified},
		{"RotateSCIMToken", "Identity Providers", "Rotate SCIM token", TargetUnspecified},
		// Identity Links
		{"ListIdentityLinks", "Authentication", "View own linked identities", TargetUnspecified},
		{"UnlinkIdentity", "Authentication", "Unlink own identity", TargetUnspecified},
		// Search — single gate-only permission; per-facet scope
		// inherits from ListDevices / ListUsers / ListActions
		// already in the actor's JWT. Search itself stays
		// TargetUnspecified so the kind-matching invariant doesn't
		// constrain it. See #7 Valkey-search section.
		{"Search", "Search", "Search across entities", TargetUnspecified},
		{"RebuildSearchIndex", "Search", "Force rebuild search index", TargetUnspecified},
		// Server Settings — org-tier
		{"GetServerSettings", "Server Settings", "View server settings", TargetUnspecified},
		{"UpdateServerSettings", "Server Settings", "Update server settings", TargetUnspecified},
		// User Provisioning
		{"SetUserProvisioningEnabled", "Users", "Toggle user provisioning per user", TargetUser},
		// Remote Terminal — the V1 user-facing consumer of scoping.
		// TerminalAdmin* per-scope grants drive the cohort
		// computation in the reconciler (#7 S6).
		{"StartTerminal", "Remote Terminal", "Open a remote terminal session on a device", TargetDevice},
		{"StopTerminal", "Remote Terminal", "Stop a remote terminal session you opened", TargetDevice},
		{"ListActiveTerminalSessions", "Remote Terminal", "View active terminal sessions across all devices (admin)", TargetDevice},
		{"TerminateTerminalSession", "Remote Terminal", "Forcibly terminate any terminal session (admin)", TargetDevice},
		{"TerminalAdminLimited", "Remote Terminal", "Grant a passwordless LIMITED sudoers policy in remote terminal sessions", TargetDevice},
		{"TerminalAdminFull", "Remote Terminal", "Grant a passwordless FULL sudoers policy in remote terminal sessions", TargetDevice},
	}
}

// AdminPermissions returns all permission keys for the Admin role.
func AdminPermissions() []string {
	perms := make([]string, len(AllPermissions()))
	for i, p := range AllPermissions() {
		perms[i] = p.Key
	}
	return perms
}

// DefaultUserPermissions returns the self-service permission set for the User role.
func DefaultUserPermissions() []string {
	return []string{
		"GetCurrentUser",
		"GetUser:self",
		"UpdateUserEmail:self",
		"UpdateUserPassword:self",
		"UpdateUserProfile:self",
		"SetupTOTP",
		"VerifyTOTP",
		"DisableTOTP",
		"GetTOTPStatus",
		"RegenerateBackupCodes",
		"ListDevices:assigned",
		"GetDevice:assigned",
		"CreateToken:self",
		"SetUserSelection",
		"ListAvailableActions",
		"ListIdentityLinks",
		"UnlinkIdentity",
		"GetDeviceCompliance:assigned",
		"UpdateUserSshSettings:self",
		"UpdateUserLinuxUsername:self",
		"AddUserSshKey:self",
		"RemoveUserSshKey:self",
		"StopTerminal",
	}
}

// ValidPermissionKeys returns a set of all valid permission keys.
func ValidPermissionKeys() map[string]bool {
	m := make(map[string]bool)
	for _, p := range AllPermissions() {
		m[p.Key] = true
	}
	return m
}

// permTargetKinds indexes permission key -> target kind, built once from
// AllPermissions so the role-assignment handler can validate scopability
// without rescanning the slice per call.
var permTargetKinds = func() map[string]PermissionTargetKind {
	m := make(map[string]PermissionTargetKind)
	for _, p := range AllPermissions() {
		m[p.Key] = p.TargetKind
	}
	return m
}()

// TargetKindFor returns the target kind of a permission key. An unknown
// key (or the zero value) is TargetUnspecified — not scopable — which is
// the safe default for the self-discovering scopability check (#7 S5).
func TargetKindFor(key string) PermissionTargetKind {
	return permTargetKinds[key]
}
