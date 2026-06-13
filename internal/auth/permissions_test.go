package auth

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAllPermissions_NotEmpty(t *testing.T) {
	perms := AllPermissions()
	assert.Greater(t, len(perms), 50, "should have many permissions")
}

func TestAllPermissions_HasRequiredGroups(t *testing.T) {
	perms := AllPermissions()
	groups := make(map[string]bool)
	for _, p := range perms {
		groups[p.Group] = true
	}

	requiredGroups := []string{
		"Users", "Devices", "Tokens", "Actions", "Action Sets",
		"Definitions", "Device Groups", "Assignments", "Dispatch",
		"Executions", "Audit", "Roles",
	}
	for _, g := range requiredGroups {
		assert.True(t, groups[g], "missing group: %s", g)
	}
}

func TestAllPermissions_KeysAreNonEmpty(t *testing.T) {
	for _, p := range AllPermissions() {
		assert.NotEmpty(t, p.Key, "permission key should not be empty")
		assert.NotEmpty(t, p.Group, "permission group should not be empty")
		assert.NotEmpty(t, p.Description, "permission description should not be empty")
	}
}

func TestAllPermissions_ScopeFormat(t *testing.T) {
	for _, p := range AllPermissions() {
		parts := strings.SplitN(p.Key, ":", 2)
		if len(parts) == 2 {
			scope := parts[1]
			assert.Contains(t, []string{"self", "assigned"}, scope,
				"invalid scope suffix in permission %s", p.Key)
		}
	}
}

func TestAdminPermissions_IncludesAllScopes(t *testing.T) {
	perms := make(map[string]bool)
	for _, p := range AdminPermissions() {
		perms[p] = true
	}
	// Admin should have both base and scoped variants
	for _, p := range AllPermissions() {
		assert.True(t, perms[p.Key], "admin should have permission: %s", p.Key)
	}
}

func TestAdminPermissions_NotEmpty(t *testing.T) {
	perms := AdminPermissions()
	assert.Greater(t, len(perms), 40, "should have many admin permissions")
}

func TestAdminPermissions_ContainsRolePerms(t *testing.T) {
	perms := make(map[string]bool)
	for _, p := range AdminPermissions() {
		perms[p] = true
	}
	assert.True(t, perms["CreateRole"])
	assert.True(t, perms["UpdateRole"])
	assert.True(t, perms["DeleteRole"])
	assert.True(t, perms["AssignRoleToUser"])
	assert.True(t, perms["RevokeRoleFromUser"])
	assert.True(t, perms["ListPermissions"])
}

func TestDefaultUserPermissions_AreValid(t *testing.T) {
	valid := ValidPermissionKeys()
	for _, p := range DefaultUserPermissions() {
		assert.True(t, valid[p], "default user permission %s is not in valid set", p)
	}
}

func TestDefaultUserPermissions_HasSelfScopes(t *testing.T) {
	perms := DefaultUserPermissions()
	hasSelf := false
	hasAssigned := false
	for _, p := range perms {
		if strings.HasSuffix(p, ":self") {
			hasSelf = true
		}
		if strings.HasSuffix(p, ":assigned") {
			hasAssigned = true
		}
	}
	assert.True(t, hasSelf, "should have :self scoped permissions")
	assert.True(t, hasAssigned, "should have :assigned scoped permissions")
}

func TestDefaultUserPermissions_IncludesBasics(t *testing.T) {
	perms := make(map[string]bool)
	for _, p := range DefaultUserPermissions() {
		perms[p] = true
	}
	assert.True(t, perms["GetCurrentUser"])
	assert.True(t, perms["GetUser:self"])
	assert.True(t, perms["UpdateUserEmail:self"])
	assert.True(t, perms["UpdateUserPassword:self"])
	assert.True(t, perms["ListDevices:assigned"])
	assert.True(t, perms["GetDevice:assigned"])
}

func TestValidPermissionKeys_IncludesAll(t *testing.T) {
	valid := ValidPermissionKeys()
	allPerms := AllPermissions()
	require.Equal(t, len(allPerms), len(valid), "ValidPermissionKeys should match AllPermissions count")
	for _, p := range allPerms {
		assert.True(t, valid[p.Key], "missing valid key: %s", p.Key)
	}
}

func TestValidPermissionKeys_RejectsInvalid(t *testing.T) {
	valid := ValidPermissionKeys()
	assert.False(t, valid["FakePermission"])
	assert.False(t, valid[""])
	assert.False(t, valid["CreateUser:admin"])
}

func TestAdminPermissions_NoDuplicates(t *testing.T) {
	seen := make(map[string]bool)
	for _, p := range AdminPermissions() {
		assert.False(t, seen[p], "duplicate admin permission: %s", p)
		seen[p] = true
	}
}

// =============================================================================
// TerminalAdmin (Limited / Full) — manchtools/power-manage-server#70
//
// Tests pin the public contract of the two new permission keys. The
// keys are added to the registry; the reconciler in system_actions.go
// keys on them by exact string match, so a typo here would silently
// leave devices without a working terminal-admin sudoers fragment.
// =============================================================================

func TestAllPermissions_IncludesTerminalAdminLimited(t *testing.T) {
	for _, p := range AllPermissions() {
		if p.Key == "TerminalAdminLimited" {
			return
		}
	}
	t.Fatalf("TerminalAdminLimited not registered in AllPermissions()")
}

func TestAllPermissions_IncludesTerminalAdminFull(t *testing.T) {
	for _, p := range AllPermissions() {
		if p.Key == "TerminalAdminFull" {
			return
		}
	}
	t.Fatalf("TerminalAdminFull not registered in AllPermissions()")
}

func TestTerminalAdminPermissions_AreInRemoteTerminalGroup(t *testing.T) {
	for _, p := range AllPermissions() {
		if p.Key == "TerminalAdminLimited" || p.Key == "TerminalAdminFull" {
			assert.Equal(t, "Remote Terminal", p.Group,
				"TerminalAdmin permissions must live alongside StartTerminal in the Remote Terminal group so the role-builder UI surfaces them together")
		}
	}
}

func TestTerminalAdminPermissions_HaveNonEmptyDescription(t *testing.T) {
	wanted := map[string]bool{"TerminalAdminLimited": true, "TerminalAdminFull": true}
	for _, p := range AllPermissions() {
		if wanted[p.Key] {
			assert.NotEmpty(t, p.Description,
				"%s must have a description (rendered in the role-builder UI)", p.Key)
		}
	}
}

func TestValidPermissionKeys_AcceptsTerminalAdminLimited(t *testing.T) {
	assert.True(t, ValidPermissionKeys()["TerminalAdminLimited"])
}

func TestValidPermissionKeys_AcceptsTerminalAdminFull(t *testing.T) {
	assert.True(t, ValidPermissionKeys()["TerminalAdminFull"])
}

func TestAdminPermissions_IncludesTerminalAdminLimited(t *testing.T) {
	perms := make(map[string]bool)
	for _, p := range AdminPermissions() {
		perms[p] = true
	}
	assert.True(t, perms["TerminalAdminLimited"],
		"the bootstrap Admin role must include TerminalAdminLimited so a fresh deployment can grant terminal-admin without seeding a custom role first")
}

func TestAdminPermissions_IncludesTerminalAdminFull(t *testing.T) {
	perms := make(map[string]bool)
	for _, p := range AdminPermissions() {
		perms[p] = true
	}
	assert.True(t, perms["TerminalAdminFull"],
		"the bootstrap Admin role must include TerminalAdminFull")
}

// TerminalAdmin keys carry NO `:self` / `:assigned` suffix — those
// describe the older subject-scope mechanism (own-record vs any).
// #7's group-anchored scope arrives via PermissionInfo.TargetKind
// (DEVICE for these two), not via a key suffix. Pin the bare key
// shape here so a future `:self` variant can't be added silently —
// the group-anchored scope and the subject-scope mechanisms must
// stay orthogonal at the registry layer.
func TestTerminalAdminPermissions_HaveNoSubjectScopeSuffix(t *testing.T) {
	for _, p := range AllPermissions() {
		if p.Key == "TerminalAdminLimited" || p.Key == "TerminalAdminFull" {
			assert.False(t, strings.Contains(p.Key, ":"),
				"%s must remain free of `:self`/`:assigned` suffix; group-anchored scope lives on TargetKind, not the key", p.Key)
		}
	}
}

// =============================================================================
// PermissionTargetKind classification — manchtools/power-manage-server#7.
//
// Tests pin the V1 curated scopable / non-scopable sets so a future
// PR can't accidentally flip a permission's scopability. Self-
// discovering against the registry with a matches-zero guard per
// ~/.claude/skills/test-quality.md rule #4 — a registry rename or
// removal surfaces immediately rather than failing open.
//
// Wrong-data is sourced from intent (the locked design's threat
// model T-S2 and the V1 curated table), NOT from the artifact under
// test, per the global TDD rule #3.
// =============================================================================

// v1ScopableDeviceTargeted is the curated set of permissions that
// MUST carry TargetKind=TargetDevice in V1. Sourced from the locked
// #7 design's V1 curated scopable device-targeted table — every
// permission whose authorization decision is "does scope_id resolve
// to a device group containing the request's device target?"
//
// Adding to this list is a deliberate registry change; removing is
// a security regression unless the permission was also removed.
var v1ScopableDeviceTargeted = []string{
	"StartTerminal",
	"StopTerminal",
	"ListActiveTerminalSessions",
	"TerminateTerminalSession",
	"TerminalAdminLimited",
	"TerminalAdminFull",
	"GetDevice",
	"ListDevices",
	"DeleteDevice",
	"SetDeviceSyncInterval",
	"RefreshDeviceInventory",
	"QueryDeviceLogs",
	"GetDeviceLogResult",
	"DispatchAction",
	"DispatchActionSet",
	"DispatchDefinition",
	"DispatchInstantAction",
	"DispatchAssignedActions",
	"DispatchToMultiple",
	"DispatchToGroup",
	"GetExecution",
	"ListExecutions",
	"CancelExecution",
	"DispatchOSQuery",
	"GetOSQueryResult",
	"GetDeviceInventory",
	"GetDeviceCompliance",
	"GetDeviceCompliancePolicyStatus",
	"AddDeviceToGroup",
	"RemoveDeviceFromGroup",
	"RenameDeviceGroup",
	"UpdateDeviceGroupDescription",
	"DeleteDeviceGroup",
	"SetDeviceGroupSyncInterval",
	"SetDeviceGroupMaintenanceWindow",
	"ListDeviceGroupsForDevice",
	"GetDeviceGroup",
	"ListDeviceGroups",
}

// v1ScopableUserTargeted is the curated set of permissions that
// MUST carry TargetKind=TargetUser. Same rationale as device.
var v1ScopableUserTargeted = []string{
	"GetUser",
	"ListUsers",
	"UpdateUserEmail",
	"UpdateUserPassword",
	"UpdateUserProfile",
	"SetUserDisabled",
	"DeleteUser",
	"UpdateUserSshSettings",
	"UpdateUserLinuxUsername",
	"AddUserSshKey",
	"RemoveUserSshKey",
	"AddUserToGroup",
	"RemoveUserFromGroup",
	"UpdateUserGroup",
	"DeleteUserGroup",
	"SetUserGroupMaintenanceWindow",
	"GetUserGroup",
	"ListUserGroups",
	"ListUserGroupsForUser",
	"AdminDisableUserTOTP",
	"SetUserProvisioningEnabled",
}

// v1NonScopableDangerous is the curated set of permissions that
// MUST stay TargetKind=TargetUnspecified because granting them with
// scope would either:
//   - silently perturb OTHER actors' scopes (labels, dynamic queries
//     — T-S2 transitive privilege escalation), or
//   - hand the holder cross-scope authority (AssignRoleScope itself
//     — T-S7 scope-authority sprawl).
//
// A future PR that flips one of these to scopable fails this test
// loudly. Together with v1ScopableDeviceTargeted +
// v1ScopableUserTargeted the three lists pin scopability in BOTH
// directions, which closes the silent-allowlist gap (test-quality
// skill rule #4).
var v1NonScopableDangerous = []string{
	// Label perms feed dynamic-query device groups
	"SetDeviceLabel",
	"RemoveDeviceLabel",
	// Dynamic-group ops let the holder match arbitrary devices /
	// users, which would perturb other actors' scopes
	"CreateDynamicDeviceGroup",
	"UpdateDynamicDeviceGroupQuery",
	"EvaluateDynamicGroup",
	"ValidateDynamicQuery",
	"CreateDynamicUserGroup",
	"UpdateDynamicUserGroupQuery",
	"EvaluateDynamicUserGroup",
	"ValidateUserGroupQuery",
	// Group CREATION is org-tier: a brand-new group has no id and no
	// members, so nothing can confine a scope at create time. Marking
	// create "scopable" would be advisory-only — scope is enforced on
	// the downstream group-management + membership ops instead.
	"CreateStaticDeviceGroup",
	"CreateStaticUserGroup",
	// Scope-authority itself is org-tier — V1 stance per T-S7
	"AssignRoleScope",
	// Role management is org-tier
	"CreateRole", "UpdateRole", "DeleteRole",
	"AssignRoleToUser", "RevokeRoleFromUser",
	"AssignRoleToUserGroup", "RevokeRoleFromUserGroup",
	// Server settings, IDP, SCIM, audit are org-tier
	"GetServerSettings", "UpdateServerSettings",
	"CreateIdentityProvider", "DeleteIdentityProvider",
	"EnableSCIM", "DisableSCIM", "RotateSCIMToken",
	"ListAuditEvents",
	// Search is the gate-only single permission; per-facet scope
	// inherits from ListDevices / ListUsers in the JWT
	"Search",
	// Security-sensitive credential views — org-tier
	"GetDeviceLpsPasswords",
	"GetDeviceLuksKeys",
	"CreateLuksToken",
	"RevokeLuksDeviceKey",
}

// indexAllByKey returns a key→PermissionInfo map for self-
// discovering registry queries. Used by every TargetKind test below.
func indexAllByKey(t *testing.T) map[string]PermissionInfo {
	t.Helper()
	out := make(map[string]PermissionInfo, len(AllPermissions()))
	for _, p := range AllPermissions() {
		out[p.Key] = p
	}
	return out
}

func TestPermissionTargetKind_UnspecifiedIsZeroValue(t *testing.T) {
	// Zero value invariant: a PermissionInfo literal with no
	// explicit TargetKind must default to TargetUnspecified. Closes
	// the fail-closed contract — new permission entries that forget
	// to classify themselves land at the safe default. T-S2.
	var zero PermissionInfo
	assert.Equal(t, TargetUnspecified, zero.TargetKind,
		"zero-value TargetKind must be TargetUnspecified — fail-closed default")
}

func TestAllPermissions_EveryEntry_HasKnownTargetKind(t *testing.T) {
	// Every registered permission must carry a known TargetKind
	// enum value (Unspecified / Device / User). A future PR that
	// adds a fourth value here would be visible from this test
	// failing rather than from a runtime mystery rejection.
	for _, p := range AllPermissions() {
		switch p.TargetKind {
		case TargetUnspecified, TargetDevice, TargetUser:
			// known
		default:
			t.Errorf("permission %q has unknown TargetKind %v — extend the enum or fix the entry", p.Key, p.TargetKind)
		}
	}
}

// -----------------------------------------------------------------
// AssignRoleScope — the scope-authority gate
// -----------------------------------------------------------------

func TestAllPermissions_IncludesAssignRoleScope(t *testing.T) {
	_, ok := indexAllByKey(t)["AssignRoleScope"]
	assert.True(t, ok, "AssignRoleScope must be registered — it gates scope-authority for #7")
}

func TestAssignRoleScope_IsInRolesGroup(t *testing.T) {
	info, ok := indexAllByKey(t)["AssignRoleScope"]
	require.True(t, ok)
	assert.Equal(t, "Roles", info.Group,
		"AssignRoleScope belongs in the Roles UI group alongside AssignRoleToUser so the role-builder surfaces them together")
}

func TestAssignRoleScope_IsOrgTier_NotScopable(t *testing.T) {
	// T-S7: AssignRoleScope itself is unscoped/org-tier in V1. A
	// flip to scopable would create a two-tier scope-authority
	// delegation that this design explicitly defers.
	info, ok := indexAllByKey(t)["AssignRoleScope"]
	require.True(t, ok)
	assert.Equal(t, TargetUnspecified, info.TargetKind,
		"AssignRoleScope must stay TargetUnspecified — V1 stance per T-S7 scope-authority sprawl")
}

func TestAdminPermissions_IncludesAssignRoleScope(t *testing.T) {
	perms := make(map[string]bool, len(AdminPermissions()))
	for _, p := range AdminPermissions() {
		perms[p] = true
	}
	assert.True(t, perms["AssignRoleScope"],
		"the bootstrap Admin role must include AssignRoleScope so a fresh deployment can attach scopes without seeding a custom role first")
}

// -----------------------------------------------------------------
// Static/Dynamic group permission splits (server #7 T-S2 mitigation)
// -----------------------------------------------------------------

func TestAllPermissions_IncludesGroupCreationSplits(t *testing.T) {
	idx := indexAllByKey(t)
	for _, key := range []string{
		"CreateStaticDeviceGroup",
		"CreateDynamicDeviceGroup",
		"CreateStaticUserGroup",
		"CreateDynamicUserGroup",
	} {
		_, ok := idx[key]
		assert.True(t, ok, "split permission %q must be registered", key)
	}
}

func TestAllPermissions_RemovesLegacyCreateAndUpdateKeys(t *testing.T) {
	// The static/dynamic split removed the old single-key
	// `CreateDeviceGroup` / `CreateUserGroup` and renamed the old
	// `Update…GroupQuery` permissions to be explicitly "Dynamic" so
	// a scope-confined admin holding only the Static variant can
	// neither create NOR update dynamic groups (T-S2 update
	// pathway). Old names MUST be gone — leaving them as aliases
	// silently bypasses the split.
	idx := indexAllByKey(t)
	for _, legacy := range []string{
		"CreateDeviceGroup",
		"CreateUserGroup",
		"UpdateDeviceGroupQuery",
		"UpdateUserGroupQuery",
	} {
		_, ok := idx[legacy]
		assert.False(t, ok,
			"legacy permission %q must be removed by #7 split; presence as alias would bypass T-S2 update pathway", legacy)
	}
}

func TestCreateStaticDeviceGroup_NotScopable(t *testing.T) {
	// Reversed from the original #7 stance: group CREATION is org-tier. A
	// brand-new group has no id and no members, so there is nothing for a scope
	// to confine at create time — making it scopable would be advisory-only,
	// which the scopable==enforced rule forbids. Scope is enforced on the
	// downstream group-management + membership ops (RenameDeviceGroup,
	// AddDeviceToGroup, …) instead.
	info, ok := indexAllByKey(t)["CreateStaticDeviceGroup"]
	require.True(t, ok)
	assert.Equal(t, TargetUnspecified, info.TargetKind,
		"CreateStaticDeviceGroup must be org-tier (TargetUnspecified) — nothing to confine a scope against at create time")
}

func TestCreateDynamicDeviceGroup_NotScopable(t *testing.T) {
	info, ok := indexAllByKey(t)["CreateDynamicDeviceGroup"]
	require.True(t, ok)
	assert.Equal(t, TargetUnspecified, info.TargetKind,
		"CreateDynamicDeviceGroup must stay unscopable — dynamic queries can match arbitrary devices and perturb other scopes (T-S2)")
}

func TestCreateStaticUserGroup_NotScopable(t *testing.T) {
	// Org-tier, symmetric with CreateStaticDeviceGroup: nothing to confine a
	// scope against at create time; scope is enforced on the downstream
	// group-management + membership ops.
	info, ok := indexAllByKey(t)["CreateStaticUserGroup"]
	require.True(t, ok)
	assert.Equal(t, TargetUnspecified, info.TargetKind,
		"CreateStaticUserGroup must be org-tier (TargetUnspecified) — nothing to confine a scope against at create time")
}

func TestCreateDynamicUserGroup_NotScopable(t *testing.T) {
	info, ok := indexAllByKey(t)["CreateDynamicUserGroup"]
	require.True(t, ok)
	assert.Equal(t, TargetUnspecified, info.TargetKind,
		"CreateDynamicUserGroup must stay unscopable, symmetric with the device-group case")
}

func TestUpdateDynamicDeviceGroupQuery_NotScopable(t *testing.T) {
	info, ok := indexAllByKey(t)["UpdateDynamicDeviceGroupQuery"]
	require.True(t, ok)
	assert.Equal(t, TargetUnspecified, info.TargetKind,
		"UpdateDynamicDeviceGroupQuery must stay unscopable — modifying a query is equivalent to authoring a fresh one (T-S2 update pathway)")
}

func TestUpdateDynamicUserGroupQuery_NotScopable(t *testing.T) {
	info, ok := indexAllByKey(t)["UpdateDynamicUserGroupQuery"]
	require.True(t, ok)
	assert.Equal(t, TargetUnspecified, info.TargetKind,
		"UpdateDynamicUserGroupQuery must stay unscopable, symmetric")
}

func TestAdminPermissions_IncludesAllGroupSplits(t *testing.T) {
	perms := make(map[string]bool, len(AdminPermissions()))
	for _, p := range AdminPermissions() {
		perms[p] = true
	}
	for _, key := range []string{
		"CreateStaticDeviceGroup",
		"CreateDynamicDeviceGroup",
		"CreateStaticUserGroup",
		"CreateDynamicUserGroup",
		"UpdateDynamicDeviceGroupQuery",
		"UpdateDynamicUserGroupQuery",
	} {
		assert.True(t, perms[key], "Admin role must include split key %q", key)
	}
}

// -----------------------------------------------------------------
// TerminalAdmin classification (V1 user-facing scope demo)
// -----------------------------------------------------------------

func TestTerminalAdminLimited_TargetsDevice(t *testing.T) {
	info, ok := indexAllByKey(t)["TerminalAdminLimited"]
	require.True(t, ok)
	assert.Equal(t, TargetDevice, info.TargetKind,
		"TerminalAdminLimited is the V1 user-facing scope demo — must be TargetDevice so the reconciler can compute per-scope cohorts")
}

func TestTerminalAdminFull_TargetsDevice(t *testing.T) {
	info, ok := indexAllByKey(t)["TerminalAdminFull"]
	require.True(t, ok)
	assert.Equal(t, TargetDevice, info.TargetKind,
		"TerminalAdminFull must be TargetDevice, symmetric with Limited")
}

// -----------------------------------------------------------------
// Self-discovering V1 curated set asserts (T-S2)
// -----------------------------------------------------------------

func TestV1ScopableDeviceTargeted_CuratedSet_AllPresentAndClassified(t *testing.T) {
	// Matches-zero guard: if the curated list shrinks to empty,
	// the test fails loudly so a future PR can't silently delete
	// the scopable set and pass.
	require.NotEmpty(t, v1ScopableDeviceTargeted,
		"v1ScopableDeviceTargeted curated list is empty — guard against vacuous pass")

	idx := indexAllByKey(t)
	for _, key := range v1ScopableDeviceTargeted {
		info, ok := idx[key]
		require.True(t, ok, "curated key %q is not registered — registry drift", key)
		assert.Equalf(t, TargetDevice, info.TargetKind,
			"curated device-targeted permission %q must be TargetDevice; found %v", key, info.TargetKind)
	}
}

func TestV1ScopableUserTargeted_CuratedSet_AllPresentAndClassified(t *testing.T) {
	require.NotEmpty(t, v1ScopableUserTargeted,
		"v1ScopableUserTargeted curated list is empty — guard against vacuous pass")

	idx := indexAllByKey(t)
	for _, key := range v1ScopableUserTargeted {
		info, ok := idx[key]
		require.True(t, ok, "curated key %q is not registered — registry drift", key)
		assert.Equalf(t, TargetUser, info.TargetKind,
			"curated user-targeted permission %q must be TargetUser; found %v", key, info.TargetKind)
	}
}

func TestV1NonScopableDangerous_CuratedSet_AllStayUnspecified(t *testing.T) {
	// The inverse guard — pins the "must stay unscopable" set so
	// a future PR can't flip a label perm / dynamic-group op /
	// AssignRoleScope to scopable without this test failing.
	require.NotEmpty(t, v1NonScopableDangerous,
		"v1NonScopableDangerous curated list is empty — guard against vacuous pass")

	idx := indexAllByKey(t)
	for _, key := range v1NonScopableDangerous {
		info, ok := idx[key]
		require.True(t, ok, "curated key %q is not registered — registry drift", key)
		assert.Equalf(t, TargetUnspecified, info.TargetKind,
			"curated non-scopable permission %q must be TargetUnspecified; flipping it scopable bypasses T-S2 / T-S7", key)
	}
}

// -----------------------------------------------------------------
// Subject-scope (':self'/':assigned') × group-scope (TargetKind)
// invariant: the two scope mechanisms are orthogonal at the
// registry layer. Subject-scoped permissions are NEVER scopable in
// the group-anchored sense — they describe a self-record gate, not
// a group-membership gate.
// -----------------------------------------------------------------

func TestSelfScopedPermissions_AreNeverGroupScopable(t *testing.T) {
	found := 0
	for _, p := range AllPermissions() {
		if !strings.Contains(p.Key, ":") {
			continue
		}
		found++
		assert.Equalf(t, TargetUnspecified, p.TargetKind,
			"subject-scoped permission %q (key with `:self`/`:assigned`) must stay TargetUnspecified — the two scope mechanisms don't mix", p.Key)
	}
	// Matches-zero guard.
	require.Greater(t, found, 0, "no subject-scoped (`:self`/`:assigned`) permissions found — the registry must still carry them")
}

// -----------------------------------------------------------------
// Search permission is the single gate-only entry; per-facet scope
// inherits from ListDevices / ListUsers via JWT-baked grants per
// the locked Valkey-search section of #7. Search itself MUST stay
// unscopable so the kinds-don't-mix invariant doesn't constrain
// its dispatch shape.
// -----------------------------------------------------------------

func TestSearchPermission_IsGateOnly_NotScopable(t *testing.T) {
	info, ok := indexAllByKey(t)["Search"]
	require.True(t, ok)
	assert.Equal(t, TargetUnspecified, info.TargetKind,
		"Search is the gate-only single permission; per-facet scope inherits from ListDevices / ListUsers via JWT")
}
