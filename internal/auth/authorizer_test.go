package auth_test

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/auth"
)

const (
	subjectA = "01J0000000000000000000000A"
	subjectB = "01J0000000000000000000000B"
)

func TestAuthorize_AdmitsTheUnrestrictedTier(t *testing.T) {
	t.Parallel()
	assert.True(t, auth.Authorize(auth.AuthzInput{
		Permissions: []string{"GetUser"}, SubjectID: subjectA, SelfEligible: true,
		Action: "GetUser", ResourceID: subjectB,
	}), "the unrestricted permission reaches any target")
}

func TestAuthorize_SelfTierIsConfinedToTheActor(t *testing.T) {
	t.Parallel()
	base := auth.AuthzInput{
		Permissions: []string{"GetUser:self"}, SubjectID: subjectA, SelfEligible: true, Action: "GetUser",
	}

	own := base
	own.ResourceID = subjectA
	assert.True(t, auth.Authorize(own))

	other := base
	other.ResourceID = subjectB
	assert.False(t, auth.Authorize(other), "the self tier does not reach another subject")

	// No identified resource is a creation whose ownership the handler
	// pins; the coarse gate admits it so the handler can decide.
	unidentified := base
	assert.True(t, auth.Authorize(unidentified))
}

// A principal that cannot own resources can never take the self path,
// even asked about its own id.
func TestAuthorize_SelfTierRefusesAPrincipalThatOwnsNothing(t *testing.T) {
	t.Parallel()
	assert.False(t, auth.Authorize(auth.AuthzInput{
		Permissions:  []string{"GetUser:self"},
		SubjectID:    auth.BootstrapPrincipalID,
		SelfEligible: false,
		Action:       "GetUser",
		ResourceID:   auth.BootstrapPrincipalID,
	}))

	// And with no identified resource either: the creation short-cut is
	// still a self grant.
	assert.False(t, auth.Authorize(auth.AuthzInput{
		Permissions:  []string{"CreateToken:self"},
		SubjectID:    auth.BootstrapPrincipalID,
		SelfEligible: false,
		Action:       "CreateToken",
	}))
}

func TestAuthorize_AssignedTierDefersToTheOwnerFilter(t *testing.T) {
	t.Parallel()
	assert.True(t, auth.Authorize(auth.AuthzInput{
		Permissions: []string{"ListDevices:assigned"}, SubjectID: subjectA, SelfEligible: true,
		Action: "ListDevices",
	}), "the assigned tier admits the request so the row filter can decide what is visible")
}

func TestAuthorize_RejectsUnclassifiedAssignedAlternative(t *testing.T) {
	t.Parallel()

	assert.False(t, auth.Authorize(auth.AuthzInput{
		Permissions: []string{"DeleteDevice:assigned"}, SubjectID: subjectA, SelfEligible: true,
		Action: "DeleteDevice",
	}), "an invented :assigned tier must not bypass the base permission")
}

func TestAuthorize_RefusesWhatTheActorDoesNotHold(t *testing.T) {
	t.Parallel()
	assert.False(t, auth.Authorize(auth.AuthzInput{
		Permissions: []string{"ListUsers"}, SubjectID: subjectA, SelfEligible: true, Action: "SetUserDisabled",
	}))
	assert.False(t, auth.Authorize(auth.AuthzInput{
		Permissions: nil, SubjectID: subjectA, SelfEligible: true, Action: "ListUsers",
	}))
}

// A permission is matched exactly: a scoped variant must not satisfy a
// lookup for a different action that shares a prefix.
func TestAuthorize_MatchesPermissionKeysExactly(t *testing.T) {
	t.Parallel()
	assert.False(t, auth.Authorize(auth.AuthzInput{
		Permissions: []string{"GetUserGroup"}, SubjectID: subjectA, SelfEligible: true, Action: "GetUser",
	}), "GetUserGroup is not GetUser")
}

func TestCanOwnResources_RequiresAUserPrincipalWithAULID(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		user *auth.UserContext
		want bool
	}{
		{"an ordinary subject", &auth.UserContext{ID: subjectA, Kind: auth.PrincipalUser}, true},
		{"the reserved principal", &auth.UserContext{ID: auth.BootstrapPrincipalID, Kind: auth.PrincipalBootstrapAdmin}, false},
		{"a user principal with a non-ULID id", &auth.UserContext{ID: "not-a-ulid", Kind: auth.PrincipalUser}, false},
		{"a user principal with no id", &auth.UserContext{Kind: auth.PrincipalUser}, false},
		{"nothing at all", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.user.CanOwnResources())
		})
	}
}

func TestEnforceSelfScope_MirrorsTheAuthorizerTiers(t *testing.T) {
	t.Parallel()

	unauthenticated := context.Background()
	err := auth.EnforceSelfScope(unauthenticated, "GetUser", subjectA)
	require.Error(t, err)
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))

	selfOnly := auth.WithUser(context.Background(), &auth.UserContext{
		ID: subjectA, Kind: auth.PrincipalUser, Permissions: []string{"GetUser:self"},
	})
	assert.NoError(t, auth.EnforceSelfScope(selfOnly, "GetUser", subjectA))
	err = auth.EnforceSelfScope(selfOnly, "GetUser", subjectB)
	require.Error(t, err)
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))

	reserved := auth.WithUser(context.Background(), &auth.UserContext{
		ID: auth.BootstrapPrincipalID, Kind: auth.PrincipalBootstrapAdmin,
		Permissions: []string{"GetUser:self"},
	})
	err = auth.EnforceSelfScope(reserved, "GetUser", auth.BootstrapPrincipalID)
	require.Error(t, err)
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err),
		"a principal that is no subject cannot be its own resource")
}
