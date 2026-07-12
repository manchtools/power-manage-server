package api_test

import (
	"context"
	"log/slog"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// userScopeDriver drives one user-targeted RPC for the behavioral out-of-scope
// confinement sweep. The user family confines via EnforceUserScopeOrSelf, which
// returns PermissionDenied for a target that is neither in the caller's user
// group nor the caller itself (the :self tier).
//
// For write RPCs, readState returns the mutable state (via a privileged read) so
// the sweep can assert a denied call left it unchanged AND an allowed call
// changed it to afterAllowed. nil readState marks a read RPC.
type userScopeDriver struct {
	rpc          string // the RPC name, which is also the permission key
	call         func(ctx context.Context, st *store.Store, targetUserID string) error
	readState    func(t *testing.T, st *store.Store, adminID, targetUserID string) any
	afterAllowed any
}

func userScopeDrivers() []userScopeDriver {
	logger := slog.Default()
	uh := func(st *store.Store) *api.UserHandler { return api.NewUserHandler(st, logger, nil) }
	return []userScopeDriver{
		{
			rpc: "GetUser",
			call: func(ctx context.Context, st *store.Store, targetUserID string) error {
				_, err := uh(st).GetUser(ctx, connect.NewRequest(&pm.GetUserRequest{Id: targetUserID}))
				return err
			},
		},
		{
			rpc: "SetUserDisabled",
			call: func(ctx context.Context, st *store.Store, targetUserID string) error {
				_, err := uh(st).SetUserDisabled(ctx, connect.NewRequest(&pm.SetUserDisabledRequest{Id: targetUserID, Disabled: true}))
				return err
			},
			readState: func(t *testing.T, st *store.Store, adminID, targetUserID string) any {
				resp, err := uh(st).GetUser(testutil.AdminContext(adminID), connect.NewRequest(&pm.GetUserRequest{Id: targetUserID}))
				require.NoError(t, err)
				return resp.Msg.GetUser().GetDisabled()
			},
			afterAllowed: true,
		},
	}
}

// TestUserScopeHandlers_ConfineOutOfScope drives scopable (TargetUser) user RPCs
// through the real handler with a user-group-scoped caller and an out-of-scope
// target user (a member of a DIFFERENT user group, and NOT the caller so the
// :self tier does not apply), asserting PermissionDenied. For write RPCs it reads
// the target back with a privileged caller to assert the denied call did NOT
// mutate and the in-scope positive control DID. Per-RPC completeness for the user
// family is held by the AST permission guard (TestScopablePermissions_AllEnforced).
func TestUserScopeHandlers_ConfineOutOfScope(t *testing.T) {
	drivers := userScopeDrivers()
	require.NotEmpty(t, drivers, "no user scope drivers — the sweep would pass vacuously")

	for _, d := range drivers {
		t.Run(d.rpc, func(t *testing.T) {
			st := testutil.SetupPostgres(t)
			admin := testutil.CreateTestUser(t, st, testutil.NewID()+"@a.com", "pass", "admin")
			ugA := testutil.CreateTestUserGroup(t, st, admin, "Team A")
			ugB := testutil.CreateTestUserGroup(t, st, admin, "Team B")
			target := testutil.CreateTestUser(t, st, testutil.NewID()+"@t.com", "pass", "admin")
			testutil.AddUserToTestGroup(t, st, admin, ugA, target)

			var before any
			if d.readState != nil {
				before = d.readState(t, st, admin, target)
			}

			// Caller scoped to ugB; target is a member of ugA and is not the caller.
			err := d.call(userScoped(testutil.NewID(), d.rpc, ugB), st, target)
			require.Errorf(t, err, "%s: out-of-scope user op must error", d.rpc)
			assert.Equalf(t, connect.CodePermissionDenied, connect.CodeOf(err),
				"%s: out-of-scope user op must be PermissionDenied; got %v", d.rpc, connect.CodeOf(err))
			if d.readState != nil {
				assert.Equalf(t, before, d.readState(t, st, admin, target),
					"%s: a denied write must NOT persist", d.rpc)
			}

			// Positive control: a caller scoped to ugA (the target's group) succeeds
			// and the write actually persists.
			require.NoErrorf(t, d.call(userScoped(testutil.NewID(), d.rpc, ugA), st, target),
				"%s: in-scope user op must succeed", d.rpc)
			if d.readState != nil {
				assert.Equalf(t, d.afterAllowed, d.readState(t, st, admin, target),
					"%s: an allowed write must persist", d.rpc)
			}
		})
	}
}
