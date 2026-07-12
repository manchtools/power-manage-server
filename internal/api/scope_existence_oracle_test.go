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
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// TestUserGroupHandlers_ExistenceOracleClosed pins spec 29 S10 for the
// user-group mutation handlers: a scope-restricted caller must not be able to
// distinguish an existing-but-out-of-scope group from a nonexistent one. Both
// must return the SAME code (PermissionDenied) rather than
// PermissionDenied-vs-NotFound.
//
// The fix reorders the scope check ahead of the existence lookup (the scope
// gate reads the caller's grants from the auth context, not the DB), so an id
// outside the caller's scope — whether it exists or not — is denied before any
// lookup. This keeps the established WS3 scope-denial code (PermissionDenied)
// while removing the existence oracle; before the fix the nonexistent id fell
// through to the lookup and leaked NotFound.
func TestUserGroupHandlers_ExistenceOracleClosed(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewUserGroupHandler(st, slog.Default())
	actor := testutil.CreateTestUser(t, st, testutil.NewID()+"@a.com", "pass", "admin")

	ugInScope := testutil.CreateTestUserGroup(t, st, actor, "In Scope")
	ugOutOfScope := testutil.CreateTestUserGroup(t, st, actor, "Out Of Scope") // exists, not in scope
	nonexistent := testutil.NewID()                                            // valid ULID, no such group

	// A caller scoped to ugInScope only.
	scoped := func() context.Context {
		return userGroupScopeGrants(
			[]string{"UpdateUserGroup", "DeleteUserGroup", "RemoveUserFromGroup"},
			[]string{ugInScope},
		)
	}

	gates := []struct {
		name   string
		invoke func(ctx context.Context, groupID string) error
	}{
		{"UpdateUserGroup", func(ctx context.Context, id string) error {
			_, err := h.UpdateUserGroup(ctx, connect.NewRequest(&pm.UpdateUserGroupRequest{GroupId: id, Name: "renamed"}))
			return err
		}},
		{"DeleteUserGroup", func(ctx context.Context, id string) error {
			_, err := h.DeleteUserGroup(ctx, connect.NewRequest(&pm.DeleteUserGroupRequest{Id: id}))
			return err
		}},
		{"RemoveUserFromGroup", func(ctx context.Context, id string) error {
			_, err := h.RemoveUserFromGroup(ctx, connect.NewRequest(&pm.RemoveUserFromGroupRequest{GroupId: id, UserId: testutil.NewID()}))
			return err
		}},
	}

	for _, g := range gates {
		t.Run(g.name+" is uniform for out-of-scope existing vs nonexistent", func(t *testing.T) {
			existErr := g.invoke(scoped(), ugOutOfScope)
			require.Error(t, existErr)
			missingErr := g.invoke(scoped(), nonexistent)
			require.Error(t, missingErr)

			// The oracle is closed only if BOTH return the same code.
			assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(existErr),
				"out-of-scope existing group should be PermissionDenied")
			assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(missingErr),
				"nonexistent group must NOT leak NotFound — an out-of-scope caller cannot tell it apart from an existing one")
			assert.Equal(t, connect.CodeOf(existErr), connect.CodeOf(missingErr),
				"existence oracle: out-of-scope existing and nonexistent must return the same code")
		})
	}
}
