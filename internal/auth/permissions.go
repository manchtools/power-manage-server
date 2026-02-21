package auth

// PermissionInfo describes a single permission.
type PermissionInfo struct {
	Key         string // e.g. "CreateAction", "GetUser:self"
	Group       string // UI group: "Users", "Devices", etc.
	Description string
}

// AllPermissions returns every available permission with metadata.
func AllPermissions() []PermissionInfo {
	return []PermissionInfo{
		// Users
		{"GetCurrentUser", "Users", "View own profile"},
		{"GetUser", "Users", "View any user"},
		{"GetUser:self", "Users", "View own profile only"},
		{"ListUsers", "Users", "List all users"},
		{"CreateUser", "Users", "Create users"},
		{"UpdateUserEmail", "Users", "Change any user's email"},
		{"UpdateUserEmail:self", "Users", "Change own email"},
		{"UpdateUserPassword", "Users", "Change any user's password"},
		{"UpdateUserPassword:self", "Users", "Change own password"},
		{"SetUserDisabled", "Users", "Disable/enable users"},
		{"DeleteUser", "Users", "Delete users"},
		// Devices
		{"ListDevices", "Devices", "List all devices"},
		{"ListDevices:assigned", "Devices", "List own assigned devices"},
		{"GetDevice", "Devices", "View any device"},
		{"GetDevice:assigned", "Devices", "View own assigned devices"},
		{"SetDeviceLabel", "Devices", "Set device labels"},
		{"RemoveDeviceLabel", "Devices", "Remove device labels"},
		{"AssignDevice", "Devices", "Assign devices to users"},
		{"UnassignDevice", "Devices", "Unassign devices"},
		{"SetDeviceSyncInterval", "Devices", "Set device sync interval"},
		{"DeleteDevice", "Devices", "Delete devices"},
		// Tokens
		{"CreateToken", "Tokens", "Create registration tokens"},
		{"CreateToken:self", "Tokens", "Create one-time token for self"},
		{"GetToken", "Tokens", "View tokens"},
		{"ListTokens", "Tokens", "List tokens"},
		{"RenameToken", "Tokens", "Rename tokens"},
		{"SetTokenDisabled", "Tokens", "Disable/enable tokens"},
		{"DeleteToken", "Tokens", "Delete tokens"},
		// Actions
		{"CreateAction", "Actions", "Create actions"},
		{"GetAction", "Actions", "View actions"},
		{"ListActions", "Actions", "List actions"},
		{"RenameAction", "Actions", "Rename actions"},
		{"UpdateActionDescription", "Actions", "Update action descriptions"},
		{"UpdateActionParams", "Actions", "Update action parameters"},
		{"DeleteAction", "Actions", "Delete actions"},
		// Action Sets
		{"CreateActionSet", "Action Sets", "Create action sets"},
		{"GetActionSet", "Action Sets", "View action sets"},
		{"ListActionSets", "Action Sets", "List action sets"},
		{"RenameActionSet", "Action Sets", "Rename action sets"},
		{"UpdateActionSetDescription", "Action Sets", "Update action set descriptions"},
		{"DeleteActionSet", "Action Sets", "Delete action sets"},
		{"AddActionToSet", "Action Sets", "Add actions to sets"},
		{"RemoveActionFromSet", "Action Sets", "Remove actions from sets"},
		{"ReorderActionInSet", "Action Sets", "Reorder actions in sets"},
		// Definitions
		{"CreateDefinition", "Definitions", "Create definitions"},
		{"GetDefinition", "Definitions", "View definitions"},
		{"ListDefinitions", "Definitions", "List definitions"},
		{"RenameDefinition", "Definitions", "Rename definitions"},
		{"UpdateDefinitionDescription", "Definitions", "Update definition descriptions"},
		{"DeleteDefinition", "Definitions", "Delete definitions"},
		{"AddActionSetToDefinition", "Definitions", "Add action sets to definitions"},
		{"RemoveActionSetFromDefinition", "Definitions", "Remove action sets from definitions"},
		{"ReorderActionSetInDefinition", "Definitions", "Reorder action sets in definitions"},
		// Device Groups
		{"CreateDeviceGroup", "Device Groups", "Create device groups"},
		{"GetDeviceGroup", "Device Groups", "View device groups"},
		{"ListDeviceGroups", "Device Groups", "List device groups"},
		{"RenameDeviceGroup", "Device Groups", "Rename device groups"},
		{"UpdateDeviceGroupDescription", "Device Groups", "Update device group descriptions"},
		{"UpdateDeviceGroupQuery", "Device Groups", "Update device group queries"},
		{"DeleteDeviceGroup", "Device Groups", "Delete device groups"},
		{"AddDeviceToGroup", "Device Groups", "Add devices to groups"},
		{"RemoveDeviceFromGroup", "Device Groups", "Remove devices from groups"},
		{"ValidateDynamicQuery", "Device Groups", "Validate dynamic queries"},
		{"EvaluateDynamicGroup", "Device Groups", "Evaluate dynamic groups"},
		{"SetDeviceGroupSyncInterval", "Device Groups", "Set device group sync interval"},
		// Assignments
		{"CreateAssignment", "Assignments", "Create assignments"},
		{"DeleteAssignment", "Assignments", "Delete assignments"},
		{"ListAssignments", "Assignments", "List assignments"},
		{"GetDeviceAssignments", "Assignments", "View device assignments"},
		// User Selections
		{"SetUserSelection", "User Selections", "Manage user selections"},
		{"ListAvailableActions", "User Selections", "List available actions"},
		// Dispatch
		{"DispatchAction", "Dispatch", "Dispatch single action"},
		{"DispatchToMultiple", "Dispatch", "Dispatch to multiple devices"},
		{"DispatchAssignedActions", "Dispatch", "Sync assigned actions to device"},
		{"DispatchActionSet", "Dispatch", "Dispatch action set"},
		{"DispatchDefinition", "Dispatch", "Dispatch definition"},
		{"DispatchToGroup", "Dispatch", "Dispatch to device group"},
		{"DispatchInstantAction", "Dispatch", "Dispatch instant action"},
		// Executions
		{"GetExecution", "Executions", "View executions"},
		{"ListExecutions", "Executions", "List executions"},
		// OSQuery
		{"DispatchOSQuery", "OSQuery", "Run OSQuery on device"},
		{"GetOSQueryResult", "OSQuery", "View OSQuery results"},
		{"GetDeviceInventory", "OSQuery", "View device inventory"},
		{"RefreshDeviceInventory", "OSQuery", "Refresh device inventory"},
		// Audit
		{"ListAuditEvents", "Audit", "View audit log"},
		// LPS
		{"GetDeviceLpsPasswords", "LPS", "View LPS passwords"},
		// LUKS
		{"GetDeviceLuksKeys", "LUKS", "View LUKS keys"},
		{"CreateLuksToken", "LUKS", "Create LUKS recovery token"},
		{"RevokeLuksDeviceKey", "LUKS", "Revoke LUKS device key"},
		// TOTP
		{"SetupTOTP", "Authentication", "Set up TOTP 2FA"},
		{"VerifyTOTP", "Authentication", "Verify TOTP setup"},
		{"DisableTOTP", "Authentication", "Disable TOTP 2FA"},
		{"GetTOTPStatus", "Authentication", "View TOTP status"},
		{"RegenerateBackupCodes", "Authentication", "Regenerate backup codes"},
		// Roles
		{"CreateRole", "Roles", "Create roles"},
		{"GetRole", "Roles", "View roles"},
		{"ListRoles", "Roles", "List roles"},
		{"UpdateRole", "Roles", "Update roles"},
		{"DeleteRole", "Roles", "Delete roles"},
		{"AssignRoleToUser", "Roles", "Assign roles to users"},
		{"RevokeRoleFromUser", "Roles", "Revoke roles from users"},
		{"ListPermissions", "Roles", "List available permissions"},
	}
}

// AdminPermissions returns all unrestricted permission keys for the Admin role.
func AdminPermissions() []string {
	var perms []string
	seen := make(map[string]bool)
	for _, p := range AllPermissions() {
		// For admin, only include the base permission (no :self/:assigned suffixes)
		// since the base permission grants unrestricted access
		base := p.Key
		for i, c := range p.Key {
			if c == ':' {
				base = p.Key[:i]
				break
			}
		}
		if !seen[base] {
			perms = append(perms, base)
			seen[base] = true
		}
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
