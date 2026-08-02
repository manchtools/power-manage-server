package auth_test

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1/powermanagev1connect"
	"github.com/manchtools/power-manage/server/internal/auth"
)

func TestAssignedPermissionAlternativesAreExactAndBackedByRPCs(t *testing.T) {
	t.Parallel()

	want := []string{
		"GetDevice",
		"GetDeviceCompliance",
		"GetDeviceCompliancePolicyStatus",
		"ListDevices",
	}
	got := auth.AssignedPermissionBases()
	assert.Equal(t, want, got,
		"each :assigned tier requires an explicit ownership-filter review")

	registeredAssigned := make([]string, 0, len(want))
	for _, permission := range auth.AllPermissions() {
		if strings.HasSuffix(permission.Key, ":assigned") {
			registeredAssigned = append(registeredAssigned, strings.TrimSuffix(permission.Key, ":assigned"))
		}
	}
	sort.Strings(registeredAssigned)
	assert.Equal(t, want, registeredAssigned,
		"a registered :assigned permission without an ownership classification would fail open")

	rpcs := controlRPCNames(t)
	for _, base := range got {
		assert.True(t, rpcs[base], "%q has an assigned tier but no matching RPC", base)
	}
}

// controlRPCNames is the set of method names on the generated control
// handler. Permission keys and public procedures are checked against
// it, so the registry cannot drift away from the contract.
func controlRPCNames(t *testing.T) map[string]bool {
	t.Helper()
	iface := reflect.TypeOf((*powermanagev1connect.ControlServiceHandler)(nil)).Elem()
	out := make(map[string]bool, iface.NumMethod())
	for i := 0; i < iface.NumMethod(); i++ {
		out[iface.Method(i).Name] = true
	}
	require.NotEmpty(t, out, "no RPCs were discovered; every parity assertion below would pass vacuously")
	return out
}

func baseKey(key string) string {
	if i := strings.IndexByte(key, ':'); i >= 0 {
		return key[:i]
	}
	return key
}

// nonRPCBackedPermissions are deliberately not gated by an RPC of the
// same name:
//
//   - TerminalAdmin* gate server-side reconciliation of the sudoers
//     policy a terminal session runs under; no handler consults them.
//   - AssignRoleScope is a precondition consulted by ANOTHER
//     permission's handler — it gates the scope arguments on the
//     role-assignment RPCs.
//
// Listing them documents the intent so the parity check stays a real
// drift-catcher for "I added a permission but no handler reads it".
var nonRPCBackedPermissions = map[string]bool{
	"TerminalAdminLimited": true,
	"TerminalAdminFull":    true,
	"AssignRoleScope":      true,
}

func TestEveryPermissionIsBackedByAnRPC(t *testing.T) {
	t.Parallel()
	rpcs := controlRPCNames(t)
	perms := auth.AllPermissions()
	require.NotEmpty(t, perms)

	for _, p := range perms {
		base := baseKey(p.Key)
		if nonRPCBackedPermissions[base] || auth.PermissionIsAlternative(base) {
			continue
		}
		assert.True(t, rpcs[base],
			"permission %q names RPC %q, which does not exist on the contract", p.Key, base)
	}
}

func TestNonRPCBackedExemptionsAreNotStale(t *testing.T) {
	t.Parallel()
	registered := make(map[string]bool)
	for _, p := range auth.AllPermissions() {
		registered[baseKey(p.Key)] = true
	}
	for key := range nonRPCBackedPermissions {
		assert.True(t, registered[key],
			"%q is exempted from the parity check but is no longer a permission; the exemption now hides a real gap", key)
	}
}

func TestEveryRPCIsCoveredByAPermissionOrIsPublic(t *testing.T) {
	t.Parallel()
	rpcs := controlRPCNames(t)

	covered := make(map[string]bool, len(rpcs))
	for name := range rpcs {
		covered[name] = false
	}
	for procedure := range auth.PublicProcedures {
		covered[auth.ProcedureAction(procedure)] = true
	}
	for procedure := range auth.ProcedureAlternativesSnapshot() {
		covered[auth.ProcedureAction(procedure)] = true
	}
	for _, p := range auth.AllPermissions() {
		covered[baseKey(p.Key)] = true
	}

	var uncovered []string
	for name, ok := range covered {
		if !ok {
			uncovered = append(uncovered, name)
		}
	}
	assert.Empty(t, uncovered,
		"these RPCs are neither public nor gated by a permission, so nothing decides who may call them: %v", uncovered)
}

func TestEveryPublicProcedureNamesARealRPC(t *testing.T) {
	t.Parallel()
	rpcs := controlRPCNames(t)
	require.NotEmpty(t, auth.PublicProcedures)
	for procedure := range auth.PublicProcedures {
		assert.True(t, strings.HasPrefix(procedure, auth.ControlProcedurePrefix),
			"%q is not a control procedure path", procedure)
		assert.True(t, rpcs[auth.ProcedureAction(procedure)],
			"%q names an RPC that does not exist; the bypass would silently not apply", procedure)
	}
}

func TestProcedureAlternatives_AreExactAndReal(t *testing.T) {
	t.Parallel()
	rpcs := controlRPCNames(t)
	registered := auth.ValidPermissionKeys()

	expected := map[string][]string{
		auth.ControlProcedurePrefix + "CreateDeviceGroup":      {"CreateStaticDeviceGroup", "CreateDynamicDeviceGroup"},
		auth.ControlProcedurePrefix + "CreateUserGroup":        {"CreateStaticUserGroup", "CreateDynamicUserGroup"},
		auth.ControlProcedurePrefix + "UpdateDeviceGroupQuery": {"UpdateDynamicDeviceGroupQuery"},
		auth.ControlProcedurePrefix + "UpdateUserGroupQuery":   {"UpdateDynamicUserGroupQuery"},
		auth.ControlProcedurePrefix + "ExportAuditEvents":      {"ListAuditEvents"},
	}
	live := auth.ProcedureAlternativesSnapshot()
	require.Len(t, live, len(expected),
		"the alternatives map changed size; it decides gating for those procedures and must be reviewed")

	for procedure, wantAlts := range expected {
		gotAlts, ok := live[procedure]
		require.True(t, ok, "the alternatives map lost %q", procedure)
		assert.Equal(t, wantAlts, gotAlts)
		assert.True(t, rpcs[auth.ProcedureAction(procedure)], "%q is not a real RPC", procedure)
		for _, alt := range gotAlts {
			assert.True(t, registered[alt], "%q is not a registered permission", alt)
		}
	}
}

// The snapshot must be a copy: a caller who mutates it must not be able
// to widen the live authorization policy.
func TestProcedureAlternativesSnapshot_IsACopy(t *testing.T) {
	t.Parallel()
	first := auth.ProcedureAlternativesSnapshot()
	require.NotEmpty(t, first)

	var picked string
	for k := range first {
		picked = k
		break
	}
	first[picked] = append(first[picked], "AttackerInjectedPermission")
	first[auth.ControlProcedurePrefix+"Forged"] = []string{"AttackerInjectedPermission"}

	second := auth.ProcedureAlternativesSnapshot()
	assert.NotContains(t, second, auth.ControlProcedurePrefix+"Forged")
	assert.NotContains(t, second[picked], "AttackerInjectedPermission")
}

func TestDefaultUserPermissions_AreAllRegisteredAndSelfService(t *testing.T) {
	t.Parallel()
	registered := auth.ValidPermissionKeys()
	perms := auth.DefaultUserPermissions()
	require.NotEmpty(t, perms)

	for _, key := range perms {
		assert.True(t, registered[key], "the default user role names %q, which is not a permission", key)
		assert.False(t, auth.IsPrivilegeGranting(key),
			"the default user role must not carry %q: it can grant or widen privilege", key)
	}
}

func TestAdminPermissions_AreTheWholeRegistry(t *testing.T) {
	t.Parallel()
	all := auth.AllPermissions()
	admin := auth.AdminPermissions()
	require.Len(t, admin, len(all))

	registered := auth.ValidPermissionKeys()
	for _, key := range admin {
		assert.True(t, registered[key])
	}
}

// isExpensiveProcedure is a self-discovering matcher. It must recognise
// at least one real procedure, or the tighter per-user ceiling it gates
// would silently apply to nothing.
func TestExpensiveProcedureMatcher_RecognisesRealProcedures(t *testing.T) {
	t.Parallel()
	rpcs := controlRPCNames(t)
	var matched []string
	for name := range rpcs {
		if auth.IsExpensiveProcedure(name) {
			matched = append(matched, name)
		}
	}
	assert.NotEmpty(t, matched,
		"the heavy-procedure matcher recognises no real procedure, so its rate limit gates nothing")
}
