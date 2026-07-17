package api_test

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"

	"github.com/manchtools/power-manage/server/internal/api"
)

// TestTerminateUserSessions_EnumeratesUnscoped is the H1 (#391) regression: the
// internal revocation path must enumerate live sessions UNSCOPED, so a
// system-initiated revocation running under the listener's user-less background
// context still finds the revoked user's sessions.
//
// Before the fix TerminateUserSessions listed via the scoped
// ListActiveTerminalSessions RPC; under a context with no UserContext the scope
// filter fails closed to zero rows, so the terminate loop never ran and NO live
// session was closed — the immediate-revocation control was a silent no-op. This
// test injects two live sessions and asserts the target user's session is
// selected even under context.Background() (exactly the listener's bgCtx shape).
func TestTerminateUserSessions_EnumeratesUnscoped(t *testing.T) {
	h := api.NewTerminalHandler(nil, nil, nil, "", slog.Default())

	// Two live sessions across the fleet — one per user. The internal
	// revocation path must see BOTH regardless of caller scope.
	h.SetGatewaySessionsForTest(func(context.Context) ([]*pm.TerminalSessionInfo, error) {
		return []*pm.TerminalSessionInfo{
			{SessionId: "sess-a", UserId: "user-A", DeviceId: "dev-1"},
			{SessionId: "sess-b", UserId: "user-B", DeviceId: "dev-2"},
		}, nil
	})

	// context.Background() has no UserContext — the same shape as the revocation
	// listener's bgCtx. The scoped RPC would fail closed here; the internal path
	// must not.
	targets, err := h.SessionsForUserTest(context.Background(), "user-A")
	require.NoError(t, err)
	require.Len(t, targets, 1, "revocation must select the revoked user's session under a user-less context")
	require.Equal(t, "sess-a", targets[0].SessionId)
	require.Equal(t, "user-A", targets[0].UserId)
}
