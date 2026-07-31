package identity_test

import (
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1/powermanagev1connect"
	"github.com/manchtools/power-manage/server/internal/auth"
)

func TestRefreshToken_RotatesAndRevokesTheOldToken(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	subject := f.seedActor(grant{Permissions: []string{"GetCurrentUser"}})
	pair := f.mintPair(subject.ID, subject.Email)

	resp, err := f.client.RefreshToken(f.ctx(), connect.NewRequest(&pmv1.RefreshTokenRequest{
		RefreshToken: pair.RefreshToken,
	}))
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Msg.AccessToken)
	assert.NotEqual(t, pair.RefreshToken, resp.Msg.RefreshToken, "the refresh token rotates")

	// The spent token cannot be replayed.
	_, err = f.client.RefreshToken(f.ctx(), connect.NewRequest(&pmv1.RefreshTokenRequest{
		RefreshToken: pair.RefreshToken,
	}))
	assert.Equal(t, connect.CodeUnauthenticated, connectCodeOf(t, err))

	ops := f.operationsFor(powermanagev1connect.ControlServiceRefreshTokenProcedure)
	require.Len(t, ops, 2, "the successful rotation and the replay are both recorded")
	assert.Equal(t, "MUTATION", ops[0].Class)
	assert.Equal(t, subject.ID, ops[0].ActorID)
	rotate := f.effectWithAction(f.effectsOf(ops[0].OperationID), "ROTATE")
	assert.Equal(t, "session_token_id_sha256", rotate.EvidenceKind)
	assert.Equal(t, sha256Hex(pairJTI(t, f, pair.RefreshToken)), rotate.EvidenceFingerprint)

	assert.Equal(t, "REJECTED_AUTHENTICATION", ops[1].Class,
		"a replayed refresh token is a rejected authentication, not a failed mutation")
	assert.Empty(t, ops[1].ActorID, "a rejected attempt has no actor")
}

// Bumping a subject's session version stops their outstanding refresh
// token from producing a new session.
func TestRefreshToken_RefusesASessionMintedUnderOldAuthority(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	admin := f.seedActor(grant{Permissions: []string{"AssignRoleToUser"}})
	subject := f.seedActor(grant{Permissions: []string{"GetCurrentUser"}})
	pair := f.mintPair(subject.ID, subject.Email)

	role := f.insertRole([]string{"ListUsers"})
	_, err := f.client.AssignRoleToUser(f.ctx(), authed(&pmv1.AssignRoleToUserRequest{
		UserId: subject.ID, RoleId: role,
	}, admin.Token))
	require.NoError(t, err)

	_, err = f.client.RefreshToken(f.ctx(), connect.NewRequest(&pmv1.RefreshTokenRequest{
		RefreshToken: pair.RefreshToken,
	}))
	assert.Equal(t, connect.CodeUnauthenticated, connectCodeOf(t, err),
		"a change to what the subject may do invalidates the sessions issued before it")
}

func TestRefreshToken_RefusesADisabledSubject(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	admin := f.seedActor(grant{Permissions: []string{"SetUserDisabled"}})
	subject := f.seedActor(grant{Permissions: []string{"GetCurrentUser"}})
	pair := f.mintPair(subject.ID, subject.Email)

	_, err := f.client.SetUserDisabled(f.ctx(), authed(&pmv1.SetUserDisabledRequest{
		Id: subject.ID, Disabled: true,
	}, admin.Token))
	require.NoError(t, err)

	_, err = f.client.RefreshToken(f.ctx(), connect.NewRequest(&pmv1.RefreshTokenRequest{
		RefreshToken: pair.RefreshToken,
	}))
	assert.Equal(t, connect.CodeUnauthenticated, connectCodeOf(t, err))
}

func TestRefreshToken_RefusesAForgedToken(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	subject := f.seedSubject()
	forged := f.forgedToken(subject.ID, subject.Email, nil)

	_, err := f.client.RefreshToken(f.ctx(), connect.NewRequest(&pmv1.RefreshTokenRequest{
		RefreshToken: forged,
	}))
	assert.Equal(t, connect.CodeUnauthenticated, connectCodeOf(t, err))

	ops := f.operationsFor(powermanagev1connect.ControlServiceRefreshTokenProcedure)
	require.Len(t, ops, 1)
	assert.Equal(t, "REJECTED_AUTHENTICATION", ops[0].Class)
}

func TestRefreshToken_RejectsAnEmptyRequest(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	_, err := f.client.RefreshToken(f.ctx(), connect.NewRequest(&pmv1.RefreshTokenRequest{}))
	assert.Equal(t, connect.CodeInvalidArgument, connectCodeOf(t, err))
	assert.Zero(t, f.countAuditOperations())
}

func TestLogout_RevokesTheSessionAndIsIdempotent(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	subject := f.seedActor(grant{Permissions: []string{"GetCurrentUser"}})
	pair := f.mintPair(subject.ID, subject.Email)

	_, err := f.client.Logout(f.ctx(), connect.NewRequest(&pmv1.LogoutRequest{RefreshToken: pair.RefreshToken}))
	require.NoError(t, err)

	_, err = f.client.RefreshToken(f.ctx(), connect.NewRequest(&pmv1.RefreshTokenRequest{
		RefreshToken: pair.RefreshToken,
	}))
	assert.Equal(t, connect.CodeUnauthenticated, connectCodeOf(t, err), "the session is over")

	// Logging out twice is not an error, and the second attempt records
	// that it changed nothing.
	_, err = f.client.Logout(f.ctx(), connect.NewRequest(&pmv1.LogoutRequest{RefreshToken: pair.RefreshToken}))
	require.NoError(t, err)

	ops := f.operationsFor(powermanagev1connect.ControlServiceLogoutProcedure)
	require.Len(t, ops, 2)
	first := f.effectWithAction(f.effectsOf(ops[0].OperationID), "LOGOUT")
	assert.Equal(t, "APPLIED", first.Outcome)
	second := f.effectWithAction(f.effectsOf(ops[1].OperationID), "LOGOUT")
	assert.Equal(t, "REJECTED", second.Outcome,
		"a repeat revocation changed nothing, and the record says so")
}

// A value that is not a token at all produces the same response as a
// successful logout: the endpoint is public, and a distinguishable
// answer would let an anonymous caller test values against it.
func TestLogout_TreatsAnUnusableTokenAsAlreadyEnded(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	subject := f.seedSubject()

	_, err := f.client.Logout(f.ctx(), connect.NewRequest(&pmv1.LogoutRequest{
		RefreshToken: f.forgedToken(subject.ID, subject.Email, nil),
	}))
	require.NoError(t, err)
	assert.Zero(t, f.countAuditOperations(), "nothing was revoked, so nothing is recorded")
}

func TestGetCurrentUser_ReturnsTheCallersOwnRecord(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	group := f.insertUserGroup()
	role := f.insertRole([]string{"UpdateUserProfile"})
	_, err := f.raw.Exec(f.ctx(),
		`INSERT INTO user_group_roles (grant_id, group_id, role_id, assigned_at, assigned_by)
		 VALUES ($1, $2, $3, $4, '')`, newULID(), group, role, f.now)
	require.NoError(t, err)

	subject := f.seedActor(grant{Permissions: []string{"GetCurrentUser"}})
	f.addUserToGroup(group, subject.ID)
	provider := f.insertProvider("corp", nil)
	f.insertIdentityLink(subject.ID, provider, "external-1")

	resp, err := f.client.GetCurrentUser(f.ctx(), authed(&pmv1.GetCurrentUserRequest{}, subject.Token))
	require.NoError(t, err)
	require.NotNil(t, resp.Msg.User)
	assert.Equal(t, subject.ID, resp.Msg.User.Id)
	assert.Len(t, resp.Msg.User.RoleGrants, 1, "the caller's direct grants are reported")
	assert.Len(t, resp.Msg.User.InheritedRoles, 1, "and the roles they hold through a group")
	assert.Len(t, resp.Msg.User.IdentityLinks, 1)
	assert.Zero(t, f.countAuditOperations(), "reading your own record is not a mutation")
}

func TestGetCurrentUser_RefusesAnUnauthenticatedCaller(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	_, err := f.client.GetCurrentUser(f.ctx(), connect.NewRequest(&pmv1.GetCurrentUserRequest{}))
	assert.Equal(t, connect.CodeUnauthenticated, connectCodeOf(t, err))
}

// An authentication rejection on a protected procedure records its own
// operation class, with the presented credential reduced to a digest
// and no actor id.
func TestRejectedAuthentication_RecordsItsOwnOperationClass(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	subject := f.seedSubject()
	forged := f.forgedToken(subject.ID, subject.Email, allPermissionKeys())

	_, err := f.client.GetCurrentUser(f.ctx(), authed(&pmv1.GetCurrentUserRequest{}, forged))
	require.Error(t, err)

	op := f.onlyOperationFor(powermanagev1connect.ControlServiceGetCurrentUserProcedure)
	assert.Equal(t, "REJECTED_AUTHENTICATION", op.Class)
	assert.Equal(t, auth.AnonymousActorType, op.ActorType)
	assert.Empty(t, op.ActorID, "the attempt never authenticated, so it has no actor")
	assert.Equal(t, sha256Hex(forged), op.ActorFingerprint,
		"the presented credential is recorded as a digest, never in the clear")
	assert.Equal(t, "DENIED", op.AuthorizationOutcome)
	assert.Equal(t, "REJECTED", op.Result)
	assert.Equal(t, "not_authenticated", op.ResultCode)
	assert.Empty(t, f.effectsOf(op.OperationID), "a refused credential affected no resource")
}

// An expired token is separated from every other failure so a client
// can tell "refresh and retry" from "log in again".
func TestRejectedAuthentication_DistinguishesExpiryFromEverythingElse(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	subject := f.seedSubject()

	_, err := f.client.GetCurrentUser(f.ctx(), authed(&pmv1.GetCurrentUserRequest{},
		f.expiredToken(subject.ID, subject.Email)))
	require.Error(t, err)

	op := f.onlyOperationFor(powermanagev1connect.ControlServiceGetCurrentUserProcedure)
	assert.Equal(t, "token_expired", op.ResultCode)
}

// pairJTI extracts the token id from a refresh token, so a test can
// assert the audit digest is of THAT token rather than of some other
// value that happens to be 64 hex characters.
func pairJTI(t *testing.T, f *fixture, refreshToken string) string {
	t.Helper()
	claims, err := f.jwt.ValidateToken(refreshToken, auth.TokenTypeRefresh)
	require.NoError(t, err)
	return claims.ID
}
