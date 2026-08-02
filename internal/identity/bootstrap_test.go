package identity_test

import (
	"net/url"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1/powermanagev1connect"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/identity"
)

func TestBootstrapToken_AdmitsTheReservedPrincipalExactlyOnce(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	issued, err := f.boot.Issue(f.ctx())
	require.NoError(t, err)
	require.NotEmpty(t, issued.Token)
	assert.Contains(t, issued.URL, issued.Token, "the operator is handed a URL they can open")
	assert.Equal(t, f.now.Add(identity.DefaultBootstrapTokenTTL), issued.ExpiresAt)
	setupURL, err := url.Parse(issued.URL)
	require.NoError(t, err)
	assert.Empty(t, setupURL.RawQuery, "the bearer token must not enter proxy logs through the query string")
	fragment, err := url.ParseQuery(setupURL.Fragment)
	require.NoError(t, err)
	assert.Equal(t, issued.Token, fragment.Get("bootstrap_token"))

	// Only the digest is stored; the printed value is not recoverable.
	var storedHash string
	require.NoError(t, f.raw.QueryRow(f.ctx(),
		`SELECT value_hash FROM tokens WHERE name = 'bootstrap-admin'`).Scan(&storedHash))
	assert.Equal(t, sha256Hex(issued.Token), storedHash)
	assert.NotEqual(t, issued.Token, storedHash)

	// First presentation works.
	_, err = f.client.CreateRole(f.ctx(), bootstrapAuthed(&pmv1.CreateRoleRequest{
		Name: "Bootstrap Admins", Permissions: []string{"ListUsers"},
	}, issued.Token))
	require.NoError(t, err, "the reserved principal may define a role on a fresh deployment")

	// Second presentation of the SAME value is refused: the spend is a
	// conditional write, not a read-then-write.
	_, err = f.client.CreateRole(f.ctx(), bootstrapAuthed(&pmv1.CreateRoleRequest{
		Name: "Second Try", Permissions: []string{"ListUsers"},
	}, issued.Token))
	assert.Equal(t, connect.CodeUnauthenticated, connectCodeOf(t, err),
		"a bootstrap token is single-use")

	var uses int32
	require.NoError(t, f.raw.QueryRow(f.ctx(),
		`SELECT current_uses FROM tokens WHERE name = 'bootstrap-admin'`).Scan(&uses))
	assert.Equal(t, int32(1), uses, "the refused second attempt did not spend it again")
}

func TestBootstrapToken_AttributesItsWritesToTheReservedPrincipal(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	issued, err := f.boot.Issue(f.ctx())
	require.NoError(t, err)

	_, err = f.client.CreateRole(f.ctx(), bootstrapAuthed(&pmv1.CreateRoleRequest{
		Name: "Bootstrap Admins", Permissions: []string{"ListUsers"},
	}, issued.Token))
	require.NoError(t, err)

	op := f.onlyOperationFor(powermanagev1connect.ControlServiceCreateRoleProcedure)
	assert.Equal(t, "MUTATION", op.Class)
	assert.Equal(t, string(auth.PrincipalBootstrapAdmin), op.ActorType)
	assert.Empty(t, op.ActorID,
		"the bootstrap principal is not a subject, so it occupies no subject-id column")

	// The mint and the spend are their own audited operations.
	mint := f.onlyOperationFor("control.bootstrap-admin/Issue")
	assert.Equal(t, "BACKGROUND_WRITER", mint.Class)
	assert.Equal(t, "host_command", mint.Origin, "the authorization is possession of the host")
	mintEffect := f.effectWithAction(f.effectsOf(mint.OperationID), "ISSUE")
	assert.Equal(t, sha256Hex(issued.Token), mintEffect.EvidenceFingerprint)

	spend := f.onlyOperationFor("control.bootstrap-admin/Consume")
	spendEffect := f.effectWithAction(f.effectsOf(spend.OperationID), "CONSUME")
	assert.Equal(t, sha256Hex(issued.Token), spendEffect.EvidenceFingerprint)
}

func TestBootstrapToken_ExpiresAndIsThenUnusable(t *testing.T) {
	t.Parallel()
	f := newFixture(t, withBootstrapTTL(time.Minute))

	issued, err := f.boot.Issue(f.ctx())
	require.NoError(t, err)

	live, err := f.store.CountLiveBootstrapAdminTokens(f.ctx(), *f.clock)
	require.NoError(t, err)
	require.Equal(t, int64(1), live, "the token is presentable before its lifetime ends")

	f.advance(2 * time.Minute)

	live, err = f.store.CountLiveBootstrapAdminTokens(f.ctx(), *f.clock)
	require.NoError(t, err)
	assert.Zero(t, live)

	_, err = f.client.CreateRole(f.ctx(), bootstrapAuthed(&pmv1.CreateRoleRequest{
		Name: "Too Late", Permissions: []string{"ListUsers"},
	}, issued.Token))
	assert.Equal(t, connect.CodeUnauthenticated, connectCodeOf(t, err))

	var uses int32
	require.NoError(t, f.raw.QueryRow(f.ctx(),
		`SELECT current_uses FROM tokens WHERE name = 'bootstrap-admin'`).Scan(&uses))
	assert.Zero(t, uses, "an expired token is not spent, it is simply refused")
}

// Minting a second token retires the first, so at most one is ever
// presentable.
func TestBootstrapToken_IssuingAgainRetiresTheOutstandingToken(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	first, err := f.boot.Issue(f.ctx())
	require.NoError(t, err)
	second, err := f.boot.Issue(f.ctx())
	require.NoError(t, err)
	require.NotEqual(t, first.Token, second.Token)

	live, err := f.store.CountLiveBootstrapAdminTokens(f.ctx(), *f.clock)
	require.NoError(t, err)
	assert.Equal(t, int64(1), live)

	_, err = f.client.CreateRole(f.ctx(), bootstrapAuthed(&pmv1.CreateRoleRequest{
		Name: "From The Old Token", Permissions: []string{"ListUsers"},
	}, first.Token))
	assert.Equal(t, connect.CodeUnauthenticated, connectCodeOf(t, err))

	_, err = f.client.CreateRole(f.ctx(), bootstrapAuthed(&pmv1.CreateRoleRequest{
		Name: "From The New Token", Permissions: []string{"ListUsers"},
	}, second.Token))
	require.NoError(t, err)
}

// The reserved principal owns nothing, so no `:self` grant can admit
// it. Two independent barriers are asserted: the principal kind, and an
// id that is not a ULID and therefore cannot equal any subject's.
func TestBootstrapPrincipal_CanNeverSatisfySelf(t *testing.T) {
	t.Parallel()

	principal := &auth.UserContext{
		ID:          auth.BootstrapPrincipalID,
		Kind:        auth.PrincipalBootstrapAdmin,
		Permissions: []string{"UpdateUserEmail:self", "GetUser:self"},
	}
	assert.False(t, principal.CanOwnResources(),
		"a principal that is no subject can own no resource")

	// Even asked about ITS OWN id, the self tier does not admit it.
	assert.False(t, auth.Authorize(auth.AuthzInput{
		Permissions:  principal.Permissions,
		SubjectID:    principal.ID,
		SelfEligible: principal.CanOwnResources(),
		Action:       "UpdateUserEmail",
		ResourceID:   principal.ID,
	}), "the self tier must never admit the reserved principal")

	// The second barrier, independent of the first: were the kind ever
	// mislabelled, the id still cannot be a subject's.
	misLabelled := &auth.UserContext{ID: auth.BootstrapPrincipalID, Kind: auth.PrincipalUser}
	assert.False(t, misLabelled.CanOwnResources(),
		"the reserved id is not a ULID, so it can never equal a subject id")
}

// The reserved principal's authority is the fixed setup set and nothing
// more: it cannot reach into the parts of the API a real administrator
// owns.
func TestBootstrapPrincipal_HoldsOnlyTheSetupAuthority(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	perms := identity.BootstrapPermissions()
	require.NotEmpty(t, perms, "the bootstrap principal holds nothing; this test would pass vacuously")

	registered := make(map[string]bool)
	for _, p := range auth.AllPermissions() {
		registered[p.Key] = true
	}
	for _, key := range perms {
		assert.True(t, registered[key], "%s is not a registered permission", key)
		assert.NotContains(t, key, ":self",
			"the reserved principal owns nothing, so a self-scoped key would be unsatisfiable")
	}

	// A procedure outside the setup set is refused even with a valid
	// bootstrap token.
	issued, err := f.boot.Issue(f.ctx())
	require.NoError(t, err)
	subject := f.seedSubject()
	_, err = f.client.SetUserDisabled(f.ctx(), bootstrapAuthed(&pmv1.SetUserDisabledRequest{
		Id: subject.ID, Disabled: true,
	}, issued.Token))
	assert.Equal(t, connect.CodePermissionDenied, connectCodeOf(t, err),
		"changing subject access is not part of bringing a deployment up")
}

// A bootstrap token must not be accepted where a session token belongs:
// the schemes are distinct so the two credential kinds cannot be
// interchanged by a caller.
func TestBootstrapToken_IsNotAcceptedAsABearerToken(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	issued, err := f.boot.Issue(f.ctx())
	require.NoError(t, err)

	_, err = f.client.CreateRole(f.ctx(), authed(&pmv1.CreateRoleRequest{
		Name: "Wrong Scheme", Permissions: []string{"ListUsers"},
	}, issued.Token))
	assert.Equal(t, connect.CodeUnauthenticated, connectCodeOf(t, err),
		"a bootstrap token presented as a session bearer token is not a session")

	// And it was not spent by the refused attempt.
	var uses int32
	require.NoError(t, f.raw.QueryRow(f.ctx(),
		`SELECT current_uses FROM tokens WHERE name = 'bootstrap-admin'`).Scan(&uses))
	assert.Zero(t, uses)
}

func TestBootstrapToken_RejectsAnUnknownValue(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	_, err := f.boot.Issue(f.ctx())
	require.NoError(t, err)

	_, err = f.client.CreateRole(f.ctx(), bootstrapAuthed(&pmv1.CreateRoleRequest{
		Name: "Guessed", Permissions: []string{"ListUsers"},
	}, "not-the-token"))
	assert.Equal(t, connect.CodeUnauthenticated, connectCodeOf(t, err))

	op := f.onlyOperationFor(powermanagev1connect.ControlServiceCreateRoleProcedure)
	assert.Equal(t, "REJECTED_AUTHENTICATION", op.Class,
		"a refused bootstrap token is a rejected authentication like any other")
}
