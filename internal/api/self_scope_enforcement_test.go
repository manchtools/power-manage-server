package api_test

import (
	"log/slog"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// selfScopeForcedOwnership lists :self permissions whose RPC enforces self-scope
// NOT by rejecting a cross-user target, but by ignoring any caller-supplied
// owner and forcing self-ownership. CreateToken:self does this
// (token_handler.go): it discards req.OwnerId and mints a self-owned, one-time,
// 7-day token, so a cross-user call cannot affect another user. Such RPCs are
// exempt from the cross-user-rejection check below, but must still be listed
// here so the self-discovering coverage assertion accounts for them.
var selfScopeForcedOwnership = map[string]bool{
	"CreateToken": true,
}

// TestSelfScopedRPCsRejectCrossUser is self-discovering against the permission
// registry: for every `:self` permission, the corresponding RPC must refuse a
// caller (holding only the :self grant) who targets a DIFFERENT user — i.e. it
// must call auth.EnforceSelfScope. This is the guard that would have caught the
// UpdateUserLinuxUsername IDOR (#354), where the handler skipped the check
// entirely (the interceptor admits any :self holder because it passes an empty
// ResourceID to Authorize).
//
// A new :self permission added without either a cross-user invocation here or a
// documented forced-ownership exemption fails the coverage assertion at the end.
func TestSelfScopedRPCsRejectCrossUser(t *testing.T) {
	st := testutil.SetupPostgres(t)
	userH := api.NewUserHandler(st, slog.Default(), nil)

	caller := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "password123", "user")
	victim := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "password123", "user")
	// UserContext holds DefaultUserPermissions, i.e. the :self grants — so a
	// rejection here proves EnforceSelfScope refused a cross-user target, not
	// merely that the permission was absent.
	ctx := testutil.UserContext(caller)

	// Each invocation targets `victim` while the caller holds only :self grants.
	invocations := map[string]func() error{
		"GetUser": func() error {
			_, err := userH.GetUser(ctx, connect.NewRequest(&pm.GetUserRequest{Id: victim}))
			return err
		},
		"UpdateUserEmail": func() error {
			_, err := userH.UpdateUserEmail(ctx, connect.NewRequest(&pm.UpdateUserEmailRequest{Id: victim, Email: "attacker@example.com"}))
			return err
		},
		"UpdateUserPassword": func() error {
			_, err := userH.UpdateUserPassword(ctx, connect.NewRequest(&pm.UpdateUserPasswordRequest{Id: victim, NewPassword: "newpassword123"}))
			return err
		},
		"UpdateUserProfile": func() error {
			_, err := userH.UpdateUserProfile(ctx, connect.NewRequest(&pm.UpdateUserProfileRequest{Id: victim, DisplayName: "attacker"}))
			return err
		},
		"UpdateUserSshSettings": func() error {
			_, err := userH.UpdateUserSshSettings(ctx, connect.NewRequest(&pm.UpdateUserSshSettingsRequest{UserId: victim, SshAccessEnabled: true}))
			return err
		},
		"AddUserSshKey": func() error {
			_, err := userH.AddUserSshKey(ctx, connect.NewRequest(&pm.AddUserSshKeyRequest{UserId: victim, PublicKey: "ssh-ed25519 AAAACROSSUSER"}))
			return err
		},
		"RemoveUserSshKey": func() error {
			_, err := userH.RemoveUserSshKey(ctx, connect.NewRequest(&pm.RemoveUserSshKeyRequest{UserId: victim, KeyId: testutil.NewID()}))
			return err
		},
		// NOTE: UpdateUserLinuxUsername is intentionally absent — #354 made it
		// admin-only (no :self variant), so a stock User can't reach it at all.
	}

	for name, call := range invocations {
		t.Run(name, func(t *testing.T) {
			err := call()
			require.Errorf(t, err, "%s must reject a cross-user :self call", name)
			assert.Equalf(t, connect.CodePermissionDenied, connect.CodeOf(err),
				"%s must return PermissionDenied for a cross-user :self call (missing EnforceSelfScope?), got: %v", name, err)
		})
	}

	// Self-discovering coverage: every :self permission must be exercised above
	// or explicitly exempted, so a future :self RPC can't silently skip
	// self-scope enforcement.
	selfPerms := map[string]bool{}
	for _, p := range auth.AllPermissions() {
		if base, ok := strings.CutSuffix(p.Key, ":self"); ok {
			selfPerms[base] = true
		}
	}
	require.NotEmpty(t, selfPerms, "expected some :self permissions in the registry")
	for base := range selfPerms {
		covered := invocations[base] != nil || selfScopeForcedOwnership[base]
		assert.Truef(t, covered,
			"permission %q:self has no cross-user-rejection test and no forced-ownership exemption — add one (#354 self-scope guard)", base)
	}
}
