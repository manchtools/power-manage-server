package api_test

import (
	"context"
	"log/slog"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// Finding #3 (user side): a caller holding a TargetUser permission scoped to a
// user group may act ONLY on users in that group. Before enforcement these
// handlers used EnforceSelfScope, which waved a user-group-scoped holder through
// to ANY user (the base permission is in their flat set). Each gate now confines
// via EnforceUserScopeOrSelf. Validate runs before the scope check, so every
// request below is otherwise valid — the only thing under test is scope.
func TestUserGates_UserGroupScopeEnforced(t *testing.T) {
	st := testutil.SetupPostgres(t)
	userH := api.NewUserHandler(st, slog.Default(), nil)
	actor := testutil.CreateTestUser(t, st, testutil.NewID()+"@a.com", "pass", "admin")

	// One scope group; an IN-scope target (member) and an OUT-of-scope target.
	ug := testutil.CreateTestUserGroup(t, st, actor, "Team A")
	inScope := testutil.CreateTestUser(t, st, testutil.NewID()+"@in.com", "pass", "user")
	outScope := testutil.CreateTestUser(t, st, testutil.NewID()+"@out.com", "pass", "user")
	testutil.AddUserToTestGroup(t, st, actor, ug, inScope)

	// Caller holds each user permission scoped ONLY to ug.
	perms := []string{"GetUser", "SetUserDisabled", "DeleteUser", "SetUserProvisioningEnabled"}
	grants := make([]auth.ScopedGrant, len(perms))
	for i, p := range perms {
		grants[i] = auth.ScopedGrant{Permission: p, ScopeKind: auth.ScopeKindUserGroup, ScopeID: ug}
	}
	scoped := func() context.Context {
		return testutil.AuthContextScoped(testutil.NewID(), "scoped@test.com", perms, grants)
	}

	// Each gate, invoked against a target id. Read + mutate, both .Id and .UserId.
	gates := []struct {
		name   string
		invoke func(ctx context.Context, target string) error
	}{
		{"GetUser", func(ctx context.Context, id string) error {
			_, err := userH.GetUser(ctx, connect.NewRequest(&pm.GetUserRequest{Id: id}))
			return err
		}},
		{"SetUserDisabled", func(ctx context.Context, id string) error {
			_, err := userH.SetUserDisabled(ctx, connect.NewRequest(&pm.SetUserDisabledRequest{Id: id, Disabled: true}))
			return err
		}},
		{"DeleteUser", func(ctx context.Context, id string) error {
			_, err := userH.DeleteUser(ctx, connect.NewRequest(&pm.DeleteUserRequest{Id: id}))
			return err
		}},
		{"SetUserProvisioningEnabled", func(ctx context.Context, id string) error {
			_, err := userH.SetUserProvisioningEnabled(ctx, connect.NewRequest(&pm.SetUserProvisioningEnabledRequest{UserId: id, Enabled: true}))
			return err
		}},
	}

	for _, g := range gates {
		t.Run(g.name+" denies out-of-scope target", func(t *testing.T) {
			err := g.invoke(scoped(), outScope)
			require.Error(t, err, "a user-group-scoped caller must not act on a user outside the scope")
			assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
		})
	}

	// Sanity: the same scoped caller IS allowed for an in-scope target (proves the
	// gate confines rather than blanket-denying). GetUser is read-only / safe.
	t.Run("GetUser allows in-scope target", func(t *testing.T) {
		_, err := userH.GetUser(scoped(), connect.NewRequest(&pm.GetUserRequest{Id: inScope}))
		require.NoError(t, err)
	})
}
