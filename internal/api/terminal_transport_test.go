package api_test

import (
	"context"
	"errors"
	"testing"

	"connectrpc.com/connect"
	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/terminal"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// Spec 41 deleted the gateway, and with it two properties the routing layer had
// been providing implicitly. Deleting a mechanism is fine; silently deleting a
// property is not, so both are pinned here.

// F5. Resolving a device to its gateway used to fail when no gateway held it,
// which is what stopped an offline device from getting a terminal. With routing
// gone that check has to be explicit, or StartTerminal mints a token and appends
// TerminalSessionStarted for a session that can never be bridged.
func TestStartTerminal_OfflineDeviceIsRejected(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h, _ := newTerminalHandler(t, st)
	h.SetTerminalTransport(
		func(context.Context) ([]*pm.TerminalSessionInfo, error) { return nil, nil },
		func(context.Context, string, string, string) (bool, error) { return true, nil },
		func(string) bool { return false }, // device offline
	)

	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	setLinuxUsername(t, st, userID, "alice")
	deviceID := testutil.CreateTestDevice(t, st, "offline-host")
	testutil.AssignDeviceToUser(t, st, userID, deviceID, userID)

	_, err := h.StartTerminal(authedCtx(userID), connect.NewRequest(&pm.StartTerminalRequest{
		DeviceId: deviceID,
	}))
	require.Error(t, err, "an offline device must not yield a terminal session")
	assert.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err),
		"offline is a precondition failure, not an internal error")

	assert.Zero(t, countDeviceEventsOfType(t, st, deviceID, "TerminalSessionStarted"),
		"no session event may be appended for a device that cannot be bridged")
}

// Positive control for the above: the identical call succeeds when the device IS
// connected, so the rejection is attributable to liveness and not to a broken
// fixture.
func TestStartTerminal_ConnectedDeviceSucceeds(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h, _ := newTerminalHandler(t, st) // default transport reports connected

	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	setLinuxUsername(t, st, userID, "alice")
	deviceID := testutil.CreateTestDevice(t, st, "online-host")
	testutil.AssignDeviceToUser(t, st, userID, deviceID, userID)

	resp, err := h.StartTerminal(authedCtx(userID), connect.NewRequest(&pm.StartTerminalRequest{
		DeviceId: deviceID,
	}))
	require.NoError(t, err)
	assert.Equal(t, "wss://control.example.com/terminal", resp.Msg.TerminalUrl)
	assert.NotEmpty(t, resp.Msg.SessionToken)
	assert.Equal(t, 1, countDeviceEventsOfType(t, st, deviceID, "TerminalSessionStarted"))
}

// mintLiveSession creates a token-store session so the terminate paths have
// something real to act on.
func mintLiveSession(t *testing.T, tokens *terminal.TokenStore, userID, deviceID string) string {
	t.Helper()
	sessionID := ulid.Make().String()
	_, err := tokens.MintWithID(context.Background(), sessionID, terminal.MintParams{
		UserID:   userID,
		DeviceID: deviceID,
		TtyUser:  "pm-tty-alice",
		Cols:     80,
		Rows:     24,
	})
	require.NoError(t, err)
	return sessionID
}

// F6. An indeterminate stop must not be reported as a successful termination:
// the operator would be told a root shell is closed while it is still running.
func TestTerminateTerminalSession_IndeterminateStopFails(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h, tokens := newTerminalHandler(t, st)
	h.SetTerminalTransport(
		func(context.Context) ([]*pm.TerminalSessionInfo, error) { return nil, nil },
		func(context.Context, string, string, string) (bool, error) {
			return false, errors.New("stream write failed")
		},
		func(string) bool { return true },
	)

	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	deviceID := testutil.CreateTestDevice(t, st, "term-host")
	sessionID := mintLiveSession(t, tokens, userID, deviceID)

	_, err := h.TerminateTerminalSession(authedCtx(userID), connect.NewRequest(&pm.TerminateTerminalSessionRequest{
		SessionId: sessionID, Reason: "test",
	}))
	require.Error(t, err, "an indeterminate stop must surface as failure, not silent success")

	assert.Zero(t, countDeviceEventsOfType(t, st, deviceID, "TerminalSessionTerminated"),
		"nothing may be audited as terminated when we cannot confirm the session stopped")
}

// A session that is genuinely gone is still a successful termination: the token
// must be revoked and that revocation audited, because it is a state change.
func TestTerminateTerminalSession_AbsentSessionStillAudits(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h, tokens := newTerminalHandler(t, st)
	h.SetTerminalTransport(
		func(context.Context) ([]*pm.TerminalSessionInfo, error) { return nil, nil },
		func(context.Context, string, string, string) (bool, error) { return false, nil }, // absent, no error
		func(string) bool { return true },
	)

	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	deviceID := testutil.CreateTestDevice(t, st, "term-host-gone")
	sessionID := mintLiveSession(t, tokens, userID, deviceID)

	_, err := h.TerminateTerminalSession(authedCtx(userID), connect.NewRequest(&pm.TerminateTerminalSessionRequest{
		SessionId: sessionID, Reason: "test",
	}))
	require.NoError(t, err, "an already-ended session is a successful termination")

	assert.Equal(t, 1, countDeviceEventsOfType(t, st, deviceID, "TerminalSessionTerminated"),
		"revoking the token is a state change and must be audited even when the session had ended")
}
