package identity_test

// Structural guards. These assert properties of the registry and the
// mounted surface rather than of one request, so a future change that
// quietly widens authorization fails here before it reaches a handler
// test.

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/identity"
)

// Every permission key this package gates on must exist in the
// registry. A typo would gate on a permission nobody holds, which reads
// as "closed" until somebody widens a role to make it work.
func TestGatedPermissions_AreAllRegistered(t *testing.T) {
	t.Parallel()
	gated := identity.GatedPermissions()
	require.NotEmpty(t, gated, "no gated permissions were enumerated; this test would pass vacuously")

	registered := auth.ValidPermissionKeys()
	require.NotEmpty(t, registered)
	for _, key := range gated {
		assert.True(t, registered[key], "handler gates on %q, which is not a registered permission", key)
	}
}

// A permission that can create or widen authority must not be scopable,
// because a scope on it would not confine the authority it mints.
func TestPrivilegeGrantingPermissions_AreNeverScopable(t *testing.T) {
	t.Parallel()
	all := auth.AllPermissions()
	require.NotEmpty(t, all)

	var privileged int
	for _, p := range all {
		if !p.PrivilegeGranting {
			continue
		}
		privileged++
		assert.Equal(t, auth.TargetUnspecified, p.TargetKind,
			"%s can grant or widen privilege, so it must declare no scopable target kind", p.Key)
		assert.True(t, auth.IsPrivilegeGranting(p.Key))
	}
	require.Positive(t, privileged,
		"the registry marks nothing privilege-granting; the global-only rule would be unenforced")
}

// An unknown key is treated as privilege-granting. A key the registry
// cannot classify must not be scopable by default.
func TestUnknownPermission_IsTreatedAsPrivilegeGranting(t *testing.T) {
	t.Parallel()
	assert.True(t, auth.IsPrivilegeGranting("SomePermissionAddedTomorrow"),
		"refusing to scope what the registry cannot classify is the fail-closed answer")

	offender, found := auth.FirstPrivilegeGranting([]string{"ListUsers", "CreateRole"})
	assert.True(t, found)
	assert.Equal(t, "CreateRole", offender)

	_, found = auth.FirstPrivilegeGranting([]string{"ListUsers", "GetUser"})
	assert.False(t, found, "an ordinary read-only role is scopable")
}

// No local-credential machinery survives in the registry: human
// identity is the identity provider's business.
func TestRegistry_HasNoLocalCredentialPermissions(t *testing.T) {
	t.Parallel()
	all := auth.AllPermissions()
	require.NotEmpty(t, all)

	forbidden := map[string]bool{
		"UpdateUserPassword":      true,
		"UpdateUserPassword:self": true,
		"SetupTOTP":               true,
		"VerifyTOTP":              true,
		"DisableTOTP":             true,
		"GetTOTPStatus":           true,
		"RegenerateBackupCodes":   true,
		"AdminDisableUserTOTP":    true,
		"Login":                   true,
		"VerifyLoginTOTP":         true,
	}
	for _, p := range all {
		assert.False(t, forbidden[p.Key], "%s is a removed local-credential permission", p.Key)
	}
}

// The public procedure set is exactly the SSO handshake plus the
// session and certificate procedures that cannot carry a session token.
// Anything else appearing here would be an unauthenticated hole.
func TestPublicProcedures_AreExactlyTheUnauthenticatedSurface(t *testing.T) {
	t.Parallel()
	expected := map[string]bool{
		"/powermanage.v1.ControlService/RefreshToken":     true,
		"/powermanage.v1.ControlService/Logout":           true,
		"/powermanage.v1.ControlService/Register":         true,
		"/powermanage.v1.ControlService/RenewCertificate": true,
		"/powermanage.v1.ControlService/ListAuthMethods":  true,
		"/powermanage.v1.ControlService/GetSSOLoginURL":   true,
		"/powermanage.v1.ControlService/SSOCallback":      true,
	}
	require.Len(t, auth.PublicProcedures, len(expected),
		"the unauthenticated surface changed size; that is a deliberate act that must be reviewed")
	for procedure := range auth.PublicProcedures {
		assert.True(t, expected[procedure], "%s was made public", procedure)
	}
	// No password-login procedure can be public because none exists.
	for procedure := range auth.PublicProcedures {
		assert.NotContains(t, procedure, "Login/")
		assert.NotContains(t, procedure, "TOTP")
	}
}

// Every procedure path this package mounts belongs to the control
// service and matches the contract's canonical form.
func TestMountedProcedures_UseTheCanonicalContractPaths(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	require.NotEmpty(t, f.mounted)
	for _, p := range f.mounted {
		assert.Contains(t, p, auth.ControlProcedurePrefix,
			"%s is not a powermanage.v1 control procedure", p)
	}
}
