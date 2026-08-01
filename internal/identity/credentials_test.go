package identity_test

// The credential and authorization matrix.
//
// Every state-changing identity procedure is driven through the REAL
// interceptor chain with each kind of bad credential, and with a
// well-formed credential belonging to an actor who holds nothing. The
// procedure set is discovered from the package rather than typed out
// here, and a procedure with no case below fails the exhaustiveness
// check — so a new mutation cannot be added without its rejection paths
// being written.

import (
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1/powermanagev1connect"
	"github.com/manchtools/power-manage/server/internal/identity"
)

// call issues one procedure with the supplied bearer token and returns
// the error. Every message is otherwise VALID: these cases probe
// credentials and authority, so a validation failure would mask the
// answer.
type call func(f *fixture, token string) error

// authenticatedMutations maps each state-changing procedure that
// requires a session to a valid request for it.
//
// The public session procedures (RefreshToken, Logout) and the public
// SSO procedures are deliberately absent: they carry no session token
// by design, and their rejection paths are tested where their own
// credential lives.
var authenticatedMutations = map[string]call{
	powermanagev1connect.ControlServiceCreateIdentityProviderProcedure: func(f *fixture, token string) error {
		_, err := f.client.CreateIdentityProvider(f.ctx(), authed(&pmv1.CreateIdentityProviderRequest{
			Name:         "Corp",
			Slug:         "corp",
			ProviderType: pmv1.IdentityProviderType_IDENTITY_PROVIDER_TYPE_OIDC,
			ClientId:     "client",
			ClientSecret: "secret",
			IssuerUrl:    "https://idp.example/",
		}, token))
		return err
	},
	powermanagev1connect.ControlServiceUpdateIdentityProviderProcedure: func(f *fixture, token string) error {
		_, err := f.client.UpdateIdentityProvider(f.ctx(), authed(&pmv1.UpdateIdentityProviderRequest{
			Id:   newULID(),
			Name: "Corp",
		}, token))
		return err
	},
	powermanagev1connect.ControlServiceDeleteIdentityProviderProcedure: func(f *fixture, token string) error {
		_, err := f.client.DeleteIdentityProvider(f.ctx(), authed(&pmv1.DeleteIdentityProviderRequest{Id: newULID()}, token))
		return err
	},
	powermanagev1connect.ControlServiceEnableSCIMProcedure: func(f *fixture, token string) error {
		_, err := f.client.EnableSCIM(f.ctx(), authed(&pmv1.EnableSCIMRequest{Id: newULID()}, token))
		return err
	},
	powermanagev1connect.ControlServiceDisableSCIMProcedure: func(f *fixture, token string) error {
		_, err := f.client.DisableSCIM(f.ctx(), authed(&pmv1.DisableSCIMRequest{Id: newULID()}, token))
		return err
	},
	powermanagev1connect.ControlServiceRotateSCIMTokenProcedure: func(f *fixture, token string) error {
		_, err := f.client.RotateSCIMToken(f.ctx(), authed(&pmv1.RotateSCIMTokenRequest{Id: newULID()}, token))
		return err
	},
	powermanagev1connect.ControlServiceUnlinkIdentityProcedure: func(f *fixture, token string) error {
		_, err := f.client.UnlinkIdentity(f.ctx(), authed(&pmv1.UnlinkIdentityRequest{LinkId: newULID()}, token))
		return err
	},
	powermanagev1connect.ControlServiceCreateUserProcedure: func(f *fixture, token string) error {
		_, err := f.client.CreateUser(f.ctx(), authed(&pmv1.CreateUserRequest{Email: "new@test.example"}, token))
		return err
	},
	powermanagev1connect.ControlServiceUpdateUserEmailProcedure: func(f *fixture, token string) error {
		_, err := f.client.UpdateUserEmail(f.ctx(), authed(&pmv1.UpdateUserEmailRequest{
			Id: newULID(), Email: "moved@test.example",
		}, token))
		return err
	},
	powermanagev1connect.ControlServiceSetUserDisabledProcedure: func(f *fixture, token string) error {
		_, err := f.client.SetUserDisabled(f.ctx(), authed(&pmv1.SetUserDisabledRequest{Id: newULID(), Disabled: true}, token))
		return err
	},
	powermanagev1connect.ControlServiceUpdateUserProfileProcedure: func(f *fixture, token string) error {
		_, err := f.client.UpdateUserProfile(f.ctx(), authed(&pmv1.UpdateUserProfileRequest{
			Id: newULID(), DisplayName: "Name",
		}, token))
		return err
	},
	powermanagev1connect.ControlServiceUpdateUserLinuxUsernameProcedure: func(f *fixture, token string) error {
		_, err := f.client.UpdateUserLinuxUsername(f.ctx(), authed(&pmv1.UpdateUserLinuxUsernameRequest{
			UserId: newULID(), LinuxUsername: "alice",
		}, token))
		return err
	},
	powermanagev1connect.ControlServiceUpdateUserSshSettingsProcedure: func(f *fixture, token string) error {
		_, err := f.client.UpdateUserSshSettings(f.ctx(), authed(&pmv1.UpdateUserSshSettingsRequest{
			UserId: newULID(), SshAccessEnabled: true,
		}, token))
		return err
	},
	powermanagev1connect.ControlServiceAddUserSshKeyProcedure: func(f *fixture, token string) error {
		_, err := f.client.AddUserSshKey(f.ctx(), authed(&pmv1.AddUserSshKeyRequest{
			UserId: newULID(), PublicKey: testSSHKey,
		}, token))
		return err
	},
	powermanagev1connect.ControlServiceRemoveUserSshKeyProcedure: func(f *fixture, token string) error {
		_, err := f.client.RemoveUserSshKey(f.ctx(), authed(&pmv1.RemoveUserSshKeyRequest{
			UserId: newULID(), KeyId: newULID(),
		}, token))
		return err
	},
	powermanagev1connect.ControlServiceSetUserProvisioningEnabledProcedure: func(f *fixture, token string) error {
		_, err := f.client.SetUserProvisioningEnabled(f.ctx(), authed(&pmv1.SetUserProvisioningEnabledRequest{
			UserId: newULID(), Enabled: true,
		}, token))
		return err
	},
	powermanagev1connect.ControlServiceDeleteUserProcedure: func(f *fixture, token string) error {
		_, err := f.client.DeleteUser(f.ctx(), authed(&pmv1.DeleteUserRequest{Id: newULID()}, token))
		return err
	},
	powermanagev1connect.ControlServiceCreateUserGroupProcedure: func(f *fixture, token string) error {
		_, err := f.client.CreateUserGroup(f.ctx(), authed(&pmv1.CreateUserGroupRequest{Name: "Operators"}, token))
		return err
	},
	powermanagev1connect.ControlServiceUpdateUserGroupProcedure: func(f *fixture, token string) error {
		_, err := f.client.UpdateUserGroup(f.ctx(), authed(&pmv1.UpdateUserGroupRequest{
			GroupId: newULID(), Name: "Operators",
		}, token))
		return err
	},
	powermanagev1connect.ControlServiceDeleteUserGroupProcedure: func(f *fixture, token string) error {
		_, err := f.client.DeleteUserGroup(f.ctx(), authed(&pmv1.DeleteUserGroupRequest{Id: newULID()}, token))
		return err
	},
	powermanagev1connect.ControlServiceAddUserToGroupProcedure: func(f *fixture, token string) error {
		_, err := f.client.AddUserToGroup(f.ctx(), authed(&pmv1.AddUserToGroupRequest{
			GroupId: newULID(), UserId: newULID(),
		}, token))
		return err
	},
	powermanagev1connect.ControlServiceRemoveUserFromGroupProcedure: func(f *fixture, token string) error {
		_, err := f.client.RemoveUserFromGroup(f.ctx(), authed(&pmv1.RemoveUserFromGroupRequest{
			GroupId: newULID(), UserId: newULID(),
		}, token))
		return err
	},
	powermanagev1connect.ControlServiceSetUserGroupMaintenanceWindowProcedure: func(f *fixture, token string) error {
		_, err := f.client.SetUserGroupMaintenanceWindow(f.ctx(), authed(&pmv1.SetUserGroupMaintenanceWindowRequest{
			Id: newULID(),
		}, token))
		return err
	},
	powermanagev1connect.ControlServiceUpdateUserGroupQueryProcedure: func(f *fixture, token string) error {
		_, err := f.client.UpdateUserGroupQuery(f.ctx(), authed(&pmv1.UpdateUserGroupQueryRequest{
			Id: newULID(), IsDynamic: true, DynamicQuery: `user.disabled equals "true"`,
		}, token))
		return err
	},
	powermanagev1connect.ControlServiceEvaluateDynamicUserGroupProcedure: func(f *fixture, token string) error {
		_, err := f.client.EvaluateDynamicUserGroup(f.ctx(), authed(&pmv1.EvaluateDynamicUserGroupRequest{
			Id: newULID(),
		}, token))
		return err
	},
	powermanagev1connect.ControlServiceUpdateServerSettingsProcedure: func(f *fixture, token string) error {
		_, err := f.client.UpdateServerSettings(f.ctx(), authed(&pmv1.UpdateServerSettingsRequest{
			UserProvisioningEnabled: true,
		}, token))
		return err
	},
	powermanagev1connect.ControlServiceCreateRoleProcedure: func(f *fixture, token string) error {
		_, err := f.client.CreateRole(f.ctx(), authed(&pmv1.CreateRoleRequest{
			Name: "Auditors", Permissions: []string{"ListUsers"},
		}, token))
		return err
	},
	powermanagev1connect.ControlServiceUpdateRoleProcedure: func(f *fixture, token string) error {
		_, err := f.client.UpdateRole(f.ctx(), authed(&pmv1.UpdateRoleRequest{
			RoleId: newULID(), Name: "Auditors", Permissions: []string{"ListUsers"},
		}, token))
		return err
	},
	powermanagev1connect.ControlServiceDeleteRoleProcedure: func(f *fixture, token string) error {
		_, err := f.client.DeleteRole(f.ctx(), authed(&pmv1.DeleteRoleRequest{Id: newULID()}, token))
		return err
	},
	powermanagev1connect.ControlServiceAssignRoleToUserProcedure: func(f *fixture, token string) error {
		_, err := f.client.AssignRoleToUser(f.ctx(), authed(&pmv1.AssignRoleToUserRequest{
			UserId: newULID(), RoleId: newULID(),
		}, token))
		return err
	},
	powermanagev1connect.ControlServiceRevokeRoleFromUserProcedure: func(f *fixture, token string) error {
		_, err := f.client.RevokeRoleFromUser(f.ctx(), authed(&pmv1.RevokeRoleFromUserRequest{
			UserId: newULID(), RoleId: newULID(),
		}, token))
		return err
	},
	powermanagev1connect.ControlServiceAssignRoleToUserGroupProcedure: func(f *fixture, token string) error {
		_, err := f.client.AssignRoleToUserGroup(f.ctx(), authed(&pmv1.AssignRoleToUserGroupRequest{
			GroupId: newULID(), RoleId: newULID(),
		}, token))
		return err
	},
	powermanagev1connect.ControlServiceRevokeRoleFromUserGroupProcedure: func(f *fixture, token string) error {
		_, err := f.client.RevokeRoleFromUserGroup(f.ctx(), authed(&pmv1.RevokeRoleFromUserGroupRequest{
			GroupId: newULID(), RoleId: newULID(),
		}, token))
		return err
	},
}

// publicMutations are the state-changing procedures that deliberately
// carry no session token: the SSO handshake and the session lifecycle a
// client must be able to drive when its access token is gone.
var publicMutations = map[string]bool{
	powermanagev1connect.ControlServiceRefreshTokenProcedure:   true,
	powermanagev1connect.ControlServiceLogoutProcedure:         true,
	powermanagev1connect.ControlServiceGetSSOLoginURLProcedure: true,
	powermanagev1connect.ControlServiceSSOCallbackProcedure:    true,
}

// testSSHKey is a real, parsable ed25519 authorized-key line. The
// handler parses what it is given, so a placeholder string would test
// the rejection path by accident.
const testSSHKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB7vTk4h/lPJHZ0k5R0VpZ5cV5hFB0j2m3wKuHbLQ9pR test@example"

// Every mutation procedure is either public by design or covered by the
// matrix. A new one is uncovered until someone classifies it, which is
// what stops the matrix from quietly shrinking.
func TestMutationMatrix_CoversEveryMutationProcedure(t *testing.T) {
	t.Parallel()
	procedures := identity.MutationProcedures()
	require.NotEmpty(t, procedures, "no mutation procedures were enumerated; the matrix would pass vacuously")

	var uncovered []string
	for _, p := range procedures {
		if publicMutations[p] {
			continue
		}
		if _, ok := authenticatedMutations[p]; !ok {
			uncovered = append(uncovered, p)
		}
	}
	assert.Empty(t, uncovered,
		"these mutation procedures have no credential/authorization case; add one to authenticatedMutations or classify them in publicMutations: %v",
		uncovered)

	var stale []string
	known := make(map[string]bool, len(procedures))
	for _, p := range procedures {
		known[p] = true
	}
	for p := range authenticatedMutations {
		if !known[p] {
			stale = append(stale, p)
		}
	}
	for p := range publicMutations {
		if !known[p] {
			stale = append(stale, p)
		}
	}
	assert.Empty(t, stale, "the matrix names procedures that are not mutations: %v", stale)
}

// Every mounted procedure is classified as a mutation, ordinary read or
// sensitive read, and
// every classified procedure is mounted. Without this the audit
// coverage tests could silently skip a procedure.
func TestProcedureClassification_MatchesTheMountedSurface(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	require.NotEmpty(t, f.mounted, "nothing was mounted; the surface assertions would pass vacuously")

	classified := make(map[string]string, len(f.mounted))
	for _, p := range identity.MutationProcedures() {
		classified[p] = "mutation"
	}
	for _, p := range identity.ReadProcedures() {
		if prior, dup := classified[p]; dup {
			t.Errorf("procedure %s is classified both as %s and as a read", p, prior)
		}
		classified[p] = "read"
	}
	for _, p := range identity.SensitiveReadProcedures() {
		if prior, dup := classified[p]; dup {
			t.Errorf("procedure %s is classified both as %s and as a sensitive read", p, prior)
		}
		classified[p] = "sensitive read"
	}

	mountedSet := make(map[string]bool, len(f.mounted))
	for _, p := range f.mounted {
		mountedSet[p] = true
		if _, ok := classified[p]; !ok {
			t.Errorf("mounted procedure %s is not classified", p)
		}
	}
	for p := range classified {
		assert.True(t, mountedSet[p], "procedure %s is classified but never mounted", p)
	}
}

// A request with no credential at all is refused before the handler
// runs.
func TestMutations_RejectMissingCredential(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	for procedure, do := range authenticatedMutations {
		t.Run(shortName(procedure), func(t *testing.T) {
			err := do(f, "")
			assert.Equal(t, connect.CodeUnauthenticated, connectCodeOf(t, err))
		})
	}
}

// A token this server signed, for a real subject, but expired.
func TestMutations_RejectExpiredCredential(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	subject := f.seedSubject()
	expired := f.expiredToken(subject.ID, subject.Email)

	for procedure, do := range authenticatedMutations {
		t.Run(shortName(procedure), func(t *testing.T) {
			err := do(f, expired)
			assert.Equal(t, connect.CodeUnauthenticated, connectCodeOf(t, err))
		})
	}
}

// A token whose CLAIMS grant everything but whose signature was made
// with another key. This is the forgery case that a naive "parse the
// claims" implementation would admit.
func TestMutations_RejectForgedSignature(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	subject := f.seedSubject()
	forged := f.forgedToken(subject.ID, subject.Email, allPermissionKeys())

	for procedure, do := range authenticatedMutations {
		t.Run(shortName(procedure), func(t *testing.T) {
			err := do(f, forged)
			assert.Equal(t, connect.CodeUnauthenticated, connectCodeOf(t, err),
				"a token signed by an unknown key must never authenticate")
		})
	}
}

// A refresh token presented where an access token belongs. The
// signature verifies, so only the token-type check stands between the
// caller and a session they were not given.
func TestMutations_RejectRefreshTokenUsedAsAccessToken(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	actor := f.seedActor(grant{Permissions: allPermissionKeys()})
	pair := f.mintPair(actor.ID, actor.Email)

	for procedure, do := range authenticatedMutations {
		t.Run(shortName(procedure), func(t *testing.T) {
			err := do(f, pair.RefreshToken)
			assert.Equal(t, connect.CodeUnauthenticated, connectCodeOf(t, err))
		})
	}
}

// A real, current token for a real subject who holds nothing relevant.
//
// The answer is PermissionDenied everywhere: this caller holds no tier
// of the permission at all, so the request never reaches the handler
// that would resolve a target. The narrower rule — a caller who HOLDS
// the permission but is confined away from the target sees not-found —
// is a different question and is tested against a confined caller in
// TestScopedCaller_SeesNotFoundForSubjectOutsideScope.
func TestMutations_RejectUnauthorizedActor(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	// A subject with a role that carries exactly one unrelated
	// permission, so they authenticate and pass nothing else.
	powerless := f.seedActor(grant{Permissions: []string{"GetCurrentUser"}})

	for procedure, do := range authenticatedMutations {
		t.Run(shortName(procedure), func(t *testing.T) {
			err := do(f, powerless.Token)
			assert.Equal(t, connect.CodePermissionDenied, connectCodeOf(t, err))
		})
	}
}

// The interceptor refuses the request before the handler can run, so no
// mutation is committed on any rejection path. Counting audit
// operations is the strongest available proxy: an admitted mutation
// cannot commit without one.
func TestMutations_RejectedRequestsCommitNoMutation(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	subject := f.seedSubject()
	forged := f.forgedToken(subject.ID, subject.Email, allPermissionKeys())

	for _, do := range authenticatedMutations {
		require.Error(t, do(f, forged))
	}

	// Every recorded operation must be a rejected authentication: no
	// mutation, no background write, nothing else.
	rows, err := f.raw.Query(f.ctx(), `SELECT DISTINCT operation_class FROM audit_operations`)
	require.NoError(t, err)
	defer rows.Close()
	var classes []string
	for rows.Next() {
		var c string
		require.NoError(t, rows.Scan(&c))
		classes = append(classes, c)
	}
	require.NoError(t, rows.Err())
	require.NotEmpty(t, classes, "no audit rows at all; the rejection path recorded nothing")
	assert.Equal(t, []string{"REJECTED_AUTHENTICATION"}, classes,
		"a rejected request must record only its rejection, never a mutation")
}

func shortName(procedure string) string {
	for i := len(procedure) - 1; i >= 0; i-- {
		if procedure[i] == '/' {
			return procedure[i+1:]
		}
	}
	return procedure
}
