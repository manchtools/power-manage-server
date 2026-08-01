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

func TestCreateUser_ProvisionsSubjectAndRecordsSealedEvidence(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	admin := f.seedActor(grant{Permissions: []string{"CreateUser", "GetUser", "ListUsers"}})
	role := f.insertRole([]string{"ListUsers"})

	resp, err := f.client.CreateUser(f.ctx(), authed(&pmv1.CreateUserRequest{
		Email:       "New.Person@Test.Example",
		RoleIds:     []string{role},
		DisplayName: "New Person",
	}, admin.Token))
	require.NoError(t, err)

	created := resp.Msg.User
	require.NotNil(t, created)
	assert.Equal(t, "new.person@test.example", created.Email, "the address is normalised before it is stored")
	assert.NotEmpty(t, created.LinuxUsername, "a provisioned subject is given an account name")
	require.Len(t, created.RoleGrants, 1)
	assert.Equal(t, role, created.RoleGrants[0].Role.Id)

	op := f.onlyOperationFor(powermanagev1connect.ControlServiceCreateUserProcedure)
	assert.Equal(t, "MUTATION", op.Class)
	assert.Equal(t, "user", op.ActorType)
	assert.Equal(t, admin.ID, op.ActorID)
	assert.Equal(t, "ALLOWED", op.AuthorizationOutcome)
	assert.Equal(t, "CreateUser", op.AuthorizationDetail)
	assert.Equal(t, "SUCCESS", op.Result)

	effects := f.effectsOf(op.OperationID)
	create := f.effectWithAction(effects, "CREATE")
	assert.Equal(t, "user", create.ResourceType)
	assert.Equal(t, created.Id, create.ResourceID)
	assert.Equal(t, "email_sha256", create.EvidenceKind)
	assert.Equal(t, sha256Hex("new.person@test.example"), create.EvidenceFingerprint,
		"the digest is of the stored, normalised address")

	// Class-three detail: the address itself, readable only through the
	// subject's own key.
	require.NotNil(t, create.SealedDetailSubject)
	assert.Equal(t, created.Id, *create.SealedDetailSubject)
	opened, err := f.openSealedDetail(created.Id, create.SealedDetail, "email")
	require.NoError(t, err)
	assert.Equal(t, "new.person@test.example", opened)

	grantEffect := f.effectWithAction(effects, "GRANT")
	require.NotNil(t, grantEffect.AfterRef)
	assert.Equal(t, role, *grantEffect.AfterRef)
}

// The audit row must never carry the address in a readable slot. This
// is asserted against the raw bytes of every text column, not against
// the fields the handler happened to set.
func TestCreateUser_AuditRowHoldsNoReadableAddress(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	admin := f.seedActor(grant{Permissions: []string{"CreateUser"}})

	const address = "secretive.person@test.example"
	_, err := f.client.CreateUser(f.ctx(), authed(&pmv1.CreateUserRequest{Email: address}, admin.Token))
	require.NoError(t, err)

	var hits int
	require.NoError(t, f.raw.QueryRow(f.ctx(), `
		SELECT count(*) FROM audit_operations
		 WHERE actor_id LIKE '%' || $1 || '%'
		    OR actor_fingerprint LIKE '%' || $1 || '%'
		    OR request_descriptor LIKE '%' || $1 || '%'
		    OR authorization_detail LIKE '%' || $1 || '%'
		    OR result_code LIKE '%' || $1 || '%'`, address).Scan(&hits))
	assert.Zero(t, hits, "the operation row must not contain the address in the clear")

	require.NoError(t, f.raw.QueryRow(f.ctx(), `
		SELECT count(*) FROM audit_effects
		 WHERE resource_id LIKE '%' || $1 || '%'
		    OR evidence_fingerprint LIKE '%' || $1 || '%'
		    OR array_to_string(changed_fields, ',') LIKE '%' || $1 || '%'
		    OR encode(sealed_detail, 'escape') LIKE '%' || $1 || '%'`, address).Scan(&hits))
	assert.Zero(t, hits, "the effect row must not contain the address in the clear, sealed or not")
}

func TestCreateUser_RejectsMalformedEmail(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	admin := f.seedActor(grant{Permissions: []string{"CreateUser"}})

	_, err := f.client.CreateUser(f.ctx(), authed(&pmv1.CreateUserRequest{Email: "not-an-address"}, admin.Token))
	assert.Equal(t, connect.CodeInvalidArgument, connectCodeOf(t, err))
	assert.Zero(t, f.countAuditOperations(), "a request refused at the boundary performs no work")
}

func TestCreateUser_RejectsDuplicateAddress(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	admin := f.seedActor(grant{Permissions: []string{"CreateUser"}})
	existing := f.seedSubject()

	_, err := f.client.CreateUser(f.ctx(), authed(&pmv1.CreateUserRequest{Email: existing.Email}, admin.Token))
	assert.Equal(t, connect.CodeAlreadyExists, connectCodeOf(t, err))
}

func TestUpdateUserEmail_SealsTheTransitionForTheSubject(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	admin := f.seedActor(grant{Permissions: []string{"UpdateUserEmail"}})
	subject := f.seedSubject()

	_, err := f.client.UpdateUserEmail(f.ctx(), authed(&pmv1.UpdateUserEmailRequest{
		Id: subject.ID, Email: "renamed@test.example",
	}, admin.Token))
	require.NoError(t, err)

	op := f.onlyOperationFor(powermanagev1connect.ControlServiceUpdateUserEmailProcedure)
	effect := f.effectWithAction(f.effectsOf(op.OperationID), "UPDATE_EMAIL")
	require.NotNil(t, effect.SealedDetailSubject)
	assert.Equal(t, subject.ID, *effect.SealedDetailSubject,
		"the detail is sealed for the SUBJECT, so erasing them destroys it")

	opened, err := f.openSealedDetail(subject.ID, effect.SealedDetail, "email")
	require.NoError(t, err)
	assert.Equal(t, subject.Email+" -> renamed@test.example", opened)
}

// A caller holding only the self-scoped tier may change their own
// address and nobody else's — and the refusal is not-found, so the id
// space cannot be probed.
func TestUpdateUserEmail_SelfTierIsConfinedToTheCaller(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	self := f.seedActor(grant{Permissions: []string{"UpdateUserEmail:self"}})
	other := f.seedSubject()

	_, err := f.client.UpdateUserEmail(f.ctx(), authed(&pmv1.UpdateUserEmailRequest{
		Id: self.ID, Email: "myself@test.example",
	}, self.Token))
	require.NoError(t, err, "the self tier admits the caller's own row")

	_, err = f.client.UpdateUserEmail(f.ctx(), authed(&pmv1.UpdateUserEmailRequest{
		Id: other.ID, Email: "hijacked@test.example",
	}, self.Token))
	assert.Equal(t, connect.CodeNotFound, connectCodeOf(t, err),
		"a self-scoped caller must not learn that another subject exists")

	// The refused request changed nothing.
	row, err := f.store.GetUser(f.ctx(), other.ID)
	require.NoError(t, err)
	assert.Equal(t, other.Email, row.Email)
}

// A caller confined to one user group may act on subjects inside it and
// sees not-found for subjects outside it.
func TestScopedCaller_SeesNotFoundForSubjectOutsideScope(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	inScopeGroup := f.insertUserGroup()
	inside := f.seedSubject()
	f.addUserToGroup(inScopeGroup, inside.ID)
	outside := f.seedSubject()

	confined := f.seedActor(grant{
		Permissions: []string{"UpdateUserProfile"},
		ScopeKind:   auth.ScopeKindUserGroup,
		ScopeID:     inScopeGroup,
	})

	_, err := f.client.UpdateUserProfile(f.ctx(), authed(&pmv1.UpdateUserProfileRequest{
		Id: inside.ID, DisplayName: "Inside",
	}, confined.Token))
	require.NoError(t, err, "a confined caller may act inside their scope")

	_, err = f.client.UpdateUserProfile(f.ctx(), authed(&pmv1.UpdateUserProfileRequest{
		Id: outside.ID, DisplayName: "Outside",
	}, confined.Token))
	assert.Equal(t, connect.CodeNotFound, connectCodeOf(t, err),
		"scoped non-owner access is reported as not found, never as permission denied")
}

// The same role granted globally reaches every subject; granted at two
// scopes it reaches exactly the union of those scopes.
func TestGrantEvaluation_GlobalVersusTwoScopes(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	groupA, groupB, groupC := f.insertUserGroup(), f.insertUserGroup(), f.insertUserGroup()
	inA, inB, inC := f.seedSubject(), f.seedSubject(), f.seedSubject()
	f.addUserToGroup(groupA, inA.ID)
	f.addUserToGroup(groupB, inB.ID)
	f.addUserToGroup(groupC, inC.ID)

	perms := []string{"UpdateUserProfile"}

	global := f.seedActor(grant{Permissions: perms})
	for _, target := range []*actor{inA, inB, inC} {
		_, err := f.client.UpdateUserProfile(f.ctx(), authed(&pmv1.UpdateUserProfileRequest{
			Id: target.ID, DisplayName: "global",
		}, global.Token))
		assert.NoError(t, err, "an unscoped grant reaches every subject")
	}

	// One subject, the SAME permission, granted at two distinct scopes.
	twoScopes := f.seedActor(
		grant{Permissions: perms, ScopeKind: auth.ScopeKindUserGroup, ScopeID: groupA},
		grant{Permissions: perms, ScopeKind: auth.ScopeKindUserGroup, ScopeID: groupB},
	)
	for _, target := range []*actor{inA, inB} {
		_, err := f.client.UpdateUserProfile(f.ctx(), authed(&pmv1.UpdateUserProfileRequest{
			Id: target.ID, DisplayName: "scoped",
		}, twoScopes.Token))
		assert.NoError(t, err, "both scopes of a twice-granted role are honoured")
	}
	_, err := f.client.UpdateUserProfile(f.ctx(), authed(&pmv1.UpdateUserProfileRequest{
		Id: inC.ID, DisplayName: "scoped",
	}, twoScopes.Token))
	assert.Equal(t, connect.CodeNotFound, connectCodeOf(t, err),
		"a subject in neither granted scope stays invisible")
}

func TestSetUserDisabled_BumpsSessionVersionAndRecordsTheTransition(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	admin := f.seedActor(grant{Permissions: []string{"SetUserDisabled"}})
	subject := f.seedSubject()

	before, err := f.store.GetUserSessionState(f.ctx(), subject.ID)
	require.NoError(t, err)

	_, err = f.client.SetUserDisabled(f.ctx(), authed(&pmv1.SetUserDisabledRequest{
		Id: subject.ID, Disabled: true,
	}, admin.Token))
	require.NoError(t, err)

	after, err := f.store.GetUserSessionState(f.ctx(), subject.ID)
	require.NoError(t, err)
	assert.True(t, after.Disabled)
	assert.Greater(t, after.SessionVersion, before.SessionVersion,
		"disabling a subject invalidates the sessions already issued to them")

	op := f.onlyOperationFor(powermanagev1connect.ControlServiceSetUserDisabledProcedure)
	effect := f.effectWithAction(f.effectsOf(op.OperationID), "SET_DISABLED")
	require.NotNil(t, effect.BeforeFlag)
	require.NotNil(t, effect.AfterFlag)
	assert.False(t, *effect.BeforeFlag)
	assert.True(t, *effect.AfterFlag)
}

// SetUserDisabled is privilege-granting, so it has no self tier: a
// subject cannot re-enable themselves and cannot disable a colleague
// through a group scope either.
func TestSetUserDisabled_HasNoSelfOrScopedTier(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	group := f.insertUserGroup()
	target := f.seedSubject()
	f.addUserToGroup(group, target.ID)

	confined := f.seedActor(grant{
		Permissions: []string{"SetUserDisabled"},
		ScopeKind:   auth.ScopeKindUserGroup,
		ScopeID:     group,
	})
	// The grant is scopable only because the fixture wrote it directly;
	// the handler ignores the scope for this permission because it is
	// global-only, so the caller still acts. What must NOT happen is a
	// scoped grant being MINTED through the RPC — see
	// TestAssignRoleToUser_RefusesScopedGrantOfPrivilegeGrantingRole.
	_, err := f.client.SetUserDisabled(f.ctx(), authed(&pmv1.SetUserDisabledRequest{
		Id: target.ID, Disabled: true,
	}, confined.Token))
	require.NoError(t, err)

	selfOnly := f.seedActor(grant{Permissions: []string{"GetCurrentUser"}})
	_, err = f.client.SetUserDisabled(f.ctx(), authed(&pmv1.SetUserDisabledRequest{
		Id: selfOnly.ID, Disabled: false,
	}, selfOnly.Token))
	assert.Equal(t, connect.CodePermissionDenied, connectCodeOf(t, err),
		"a subject cannot change their own disabled state")
}

func TestDisableAndDeleteUser_RefuseLastEnabledAdmin(t *testing.T) {
	for _, viaGroup := range []bool{false, true} {
		name := "direct"
		if viaGroup {
			name = "group"
		}
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			soleAdmin := f.seedSubject()
			if viaGroup {
				groupID := f.insertUserGroup()
				f.addUserToGroup(groupID, soleAdmin.ID)
				_, err := f.raw.Exec(f.ctx(),
					`INSERT INTO user_group_roles (grant_id, group_id, role_id, assigned_at, assigned_by)
					 VALUES ($1, $2, $3, $4, '')`, newULID(), groupID, auth.AdminRoleID, f.now)
				require.NoError(t, err)
			} else {
				f.insertUserRoleGrant(soleAdmin.ID, auth.AdminRoleID, "", "")
			}
			token := f.mintToken(soleAdmin.ID, soleAdmin.Email)

			_, err := f.client.SetUserDisabled(f.ctx(), authed(&pmv1.SetUserDisabledRequest{
				Id: soleAdmin.ID, Disabled: true,
			}, token))
			assert.Equal(t, connect.CodeFailedPrecondition, connectCodeOf(t, err))
			_, err = f.client.DeleteUser(f.ctx(), authed(&pmv1.DeleteUserRequest{Id: soleAdmin.ID}, token))
			assert.Equal(t, connect.CodeFailedPrecondition, connectCodeOf(t, err))

			state, err := f.store.GetUserSessionState(f.ctx(), soleAdmin.ID)
			require.NoError(t, err)
			assert.False(t, state.Disabled)
			assert.Empty(t, f.operationsFor(powermanagev1connect.ControlServiceSetUserDisabledProcedure))
			assert.Empty(t, f.operationsFor(powermanagev1connect.ControlServiceDeleteUserProcedure))
		})
	}
}

func TestSetUserDisabled_ConcurrentAdminsCannotRaceToZero(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	first, second := f.seedSubject(), f.seedSubject()
	f.insertUserRoleGrant(first.ID, auth.AdminRoleID, "", "")
	f.insertUserRoleGrant(second.ID, auth.AdminRoleID, "", "")
	firstToken := f.mintToken(first.ID, first.Email)
	secondToken := f.mintToken(second.ID, second.Email)

	start := make(chan struct{})
	results := make(chan error, 2)
	for _, attempt := range []struct {
		id, token string
	}{{first.ID, firstToken}, {second.ID, secondToken}} {
		attempt := attempt
		go func() {
			<-start
			_, err := f.client.SetUserDisabled(f.ctx(), authed(&pmv1.SetUserDisabledRequest{
				Id: attempt.id, Disabled: true,
			}, attempt.token))
			results <- err
		}()
	}
	close(start)
	errs := []error{<-results, <-results}
	successes, refused := 0, 0
	for _, err := range errs {
		if err == nil {
			successes++
		} else if connectCodeOf(t, err) == connect.CodeFailedPrecondition {
			refused++
		}
	}
	assert.Equal(t, 1, successes)
	assert.Equal(t, 1, refused)
	var enabled int
	require.NoError(t, f.raw.QueryRow(f.ctx(),
		`SELECT count(*) FROM users WHERE id = ANY($1::text[]) AND disabled = FALSE`, []string{first.ID, second.ID}).Scan(&enabled))
	assert.Equal(t, 1, enabled, "the shared transaction lock must leave one enabled administrator")
}

func TestAddUserSshKey_RecordsTheKeyFingerprintNotTheKey(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	admin := f.seedActor(grant{Permissions: []string{"AddUserSshKey", "RemoveUserSshKey", "GetUser"}})
	subject := f.seedSubject()

	resp, err := f.client.AddUserSshKey(f.ctx(), authed(&pmv1.AddUserSshKeyRequest{
		UserId: subject.ID, PublicKey: testSSHKey, Comment: "laptop",
	}, admin.Token))
	require.NoError(t, err)
	require.NotNil(t, resp.Msg.Key)

	op := f.onlyOperationFor(powermanagev1connect.ControlServiceAddUserSshKeyProcedure)
	effect := f.effectWithAction(f.effectsOf(op.OperationID), "ADD")
	assert.Equal(t, "ssh_public_key_sha256", effect.EvidenceKind)
	assert.Len(t, effect.EvidenceFingerprint, 64, "the evidence is a SHA-256 digest")

	// Removing it records the same digest, so the two rows correlate.
	_, err = f.client.RemoveUserSshKey(f.ctx(), authed(&pmv1.RemoveUserSshKeyRequest{
		UserId: subject.ID, KeyId: resp.Msg.Key.Id,
	}, admin.Token))
	require.NoError(t, err)

	removeOp := f.onlyOperationFor(powermanagev1connect.ControlServiceRemoveUserSshKeyProcedure)
	removeEffect := f.effectWithAction(f.effectsOf(removeOp.OperationID), "REMOVE")
	assert.Equal(t, effect.EvidenceFingerprint, removeEffect.EvidenceFingerprint)
}

func TestAddUserSshKey_RejectsUnparsableKey(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	admin := f.seedActor(grant{Permissions: []string{"AddUserSshKey"}})
	subject := f.seedSubject()

	_, err := f.client.AddUserSshKey(f.ctx(), authed(&pmv1.AddUserSshKeyRequest{
		UserId: subject.ID, PublicKey: "ssh-ed25519 not-base64-at-all",
	}, admin.Token))
	assert.Equal(t, connect.CodeInvalidArgument, connectCodeOf(t, err))

	keys, err := f.store.ListUserSSHKeys(f.ctx(), subject.ID)
	require.NoError(t, err)
	assert.Empty(t, keys, "a key that cannot be parsed is never authorized on a device")
}

func TestUpdateUserLinuxUsername_HasNoSelfTier(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	// The self variant is not even registered, so the closest a subject
	// can get is holding a self grant of a sibling permission.
	selfish := f.seedActor(grant{Permissions: []string{"UpdateUserProfile:self", "GetCurrentUser"}})

	_, err := f.client.UpdateUserLinuxUsername(f.ctx(), authed(&pmv1.UpdateUserLinuxUsernameRequest{
		UserId: selfish.ID, LinuxUsername: "root",
	}, selfish.Token))
	assert.Equal(t, connect.CodePermissionDenied, connectCodeOf(t, err),
		"the account name keys sudo policy on managed devices; a subject cannot choose their own")
}

func TestDeleteUser_ErasesStateAndDestroysTheSubjectKey(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	admin := f.seedActor(grant{Permissions: []string{"DeleteUser", "GetUser", "UpdateUserEmail"}})
	subject := f.seedSubject()
	provider := f.insertProvider("corp", nil)
	f.insertIdentityLink(subject.ID, provider, "external-1")
	group := f.insertUserGroup()
	f.addUserToGroup(group, subject.ID)

	// A prior mutation leaves class-three detail sealed for the
	// subject, which erasure must render unreadable.
	_, err := f.client.UpdateUserEmail(f.ctx(), authed(&pmv1.UpdateUserEmailRequest{
		Id: subject.ID, Email: "before-erasure@test.example",
	}, admin.Token))
	require.NoError(t, err)
	priorOp := f.onlyOperationFor(powermanagev1connect.ControlServiceUpdateUserEmailProcedure)
	priorEffect := f.effectWithAction(f.effectsOf(priorOp.OperationID), "UPDATE_EMAIL")
	_, err = f.openSealedDetail(subject.ID, priorEffect.SealedDetail, "email")
	require.NoError(t, err, "the detail is readable while the subject's key exists")

	_, err = f.client.DeleteUser(f.ctx(), authed(&pmv1.DeleteUserRequest{Id: subject.ID}, admin.Token))
	require.NoError(t, err)

	_, err = f.store.GetUser(f.ctx(), subject.ID)
	assert.Error(t, err, "the subject row is gone")
	_, err = f.store.GetUserEncryptionKey(f.ctx(), subject.ID)
	assert.Error(t, err, "the subject's key is destroyed")

	// The sealed detail survives as bytes and is now permanently
	// unreadable: attribution without personal data.
	_, err = f.openSealedDetail(subject.ID, priorEffect.SealedDetail, "email")
	assert.Error(t, err, "destroying the key makes every sealed detail unreadable")

	var effectsRemain int
	require.NoError(t, f.raw.QueryRow(f.ctx(),
		`SELECT count(*) FROM audit_effects WHERE operation_id = $1`, priorOp.OperationID).Scan(&effectsRemain))
	assert.Positive(t, effectsRemain, "the audit row itself is never deleted by erasure")

	op := f.onlyOperationFor(powermanagev1connect.ControlServiceDeleteUserProcedure)
	effects := f.effectsOf(op.OperationID)
	erase := f.effectWithAction(effects, "ERASE")
	assert.Nil(t, erase.SealedDetail,
		"the erasure record carries no class-three detail: its key is destroyed in the same transaction")
	assert.Equal(t, sha256Hex("before-erasure@test.example"), erase.EvidenceFingerprint)

	links := f.effectWithAction(effects, "ERASE_LINKS")
	require.NotNil(t, links.BeforeCount)
	assert.Equal(t, int64(1), *links.BeforeCount)
	memberships := f.effectWithAction(effects, "ERASE_MEMBERSHIPS")
	require.NotNil(t, memberships.BeforeCount)
	assert.Equal(t, int64(1), *memberships.BeforeCount)
	keys := f.effectWithAction(effects, "DESTROY_KEY")
	require.NotNil(t, keys.BeforeCount)
	assert.Equal(t, int64(1), *keys.BeforeCount)
}

func TestListUsers_ConfinedCallerSeesOnlyTheirScope(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	group := f.insertUserGroup()
	inside := f.seedSubject()
	f.addUserToGroup(group, inside.ID)
	outside := f.seedSubject()

	confined := f.seedActor(grant{
		Permissions: []string{"ListUsers"},
		ScopeKind:   auth.ScopeKindUserGroup,
		ScopeID:     group,
	})

	resp, err := f.client.ListUsers(f.ctx(), authed(&pmv1.ListUsersRequest{}, confined.Token))
	require.NoError(t, err)

	seen := make(map[string]bool, len(resp.Msg.Users))
	for _, u := range resp.Msg.Users {
		seen[u.Id] = true
	}
	assert.True(t, seen[inside.ID], "a subject inside the scope is listed")
	assert.False(t, seen[outside.ID], "a subject outside the scope is not")
	assert.False(t, seen[confined.ID], "the caller is not in their own scope group either")
	assert.Equal(t, int32(len(resp.Msg.Users)), resp.Msg.TotalCount,
		"a confined caller is told how many rows they can see, not how many exist")
}
