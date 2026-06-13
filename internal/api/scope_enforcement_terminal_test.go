package api_test

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// Finding #3 (terminal session ops): StopTerminal and TerminateTerminalSession
// resolve a session id to its device and must confine a device-group-scoped
// caller to sessions on in-scope devices.
func TestStopTerminal_DeviceScopeEnforced(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h, _ := newTerminalHandler(t, st)

	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	setLinuxUsername(t, st, userID, "alice")
	dgX := testutil.CreateTestDeviceGroup(t, st, userID, "Plant X")
	devIn := testutil.CreateTestDevice(t, st, "in-scope")
	devOut := testutil.CreateTestDevice(t, st, "out-of-scope")
	testutil.AddDeviceToTestGroup(t, st, userID, dgX, devIn)

	// The caller may OPEN a session anywhere (StartTerminal unscoped) but may only
	// STOP sessions on devices in dgX (StopTerminal scoped to dgX).
	scopedCtx := testutil.AuthContextScoped(userID, "u@test.com",
		[]string{"StartTerminal", "StopTerminal"},
		[]auth.ScopedGrant{
			{Permission: "StartTerminal"},
			{Permission: "StopTerminal", ScopeKind: auth.ScopeKindDeviceGroup, ScopeID: dgX},
		})

	openSession := func(deviceID string) string {
		resp, err := h.StartTerminal(scopedCtx, connect.NewRequest(&pm.StartTerminalRequest{DeviceId: deviceID}))
		require.NoError(t, err)
		return resp.Msg.SessionId
	}

	t.Run("denies stopping a session on an out-of-scope device", func(t *testing.T) {
		sid := openSession(devOut)
		_, err := h.StopTerminal(scopedCtx, connect.NewRequest(&pm.StopTerminalRequest{SessionId: sid}))
		require.Error(t, err)
		assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
	})

	t.Run("allows stopping a session on an in-scope device", func(t *testing.T) {
		sid := openSession(devIn)
		_, err := h.StopTerminal(scopedCtx, connect.NewRequest(&pm.StopTerminalRequest{SessionId: sid}))
		require.NoError(t, err)
	})
}

func TestTerminateTerminalSession_DeviceScopeEnforced(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h, _ := newTerminalHandler(t, st)

	// A separate owner opens the sessions.
	ownerID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	setLinuxUsername(t, st, ownerID, "owner")
	ownerCtx := testutil.AuthContextScoped(ownerID, "owner@test.com",
		[]string{"StartTerminal"}, []auth.ScopedGrant{{Permission: "StartTerminal"}})

	dgX := testutil.CreateTestDeviceGroup(t, st, ownerID, "Plant X")
	devIn := testutil.CreateTestDevice(t, st, "in-scope")
	devOut := testutil.CreateTestDevice(t, st, "out-of-scope")
	testutil.AddDeviceToTestGroup(t, st, ownerID, dgX, devIn)

	openSession := func(deviceID string) string {
		resp, err := h.StartTerminal(ownerCtx, connect.NewRequest(&pm.StartTerminalRequest{DeviceId: deviceID}))
		require.NoError(t, err)
		return resp.Msg.SessionId
	}

	// The admin terminator is scoped to dgX for TerminateTerminalSession.
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	terminator := testutil.AuthContextScoped(adminID, "admin@test.com",
		[]string{"TerminateTerminalSession"},
		[]auth.ScopedGrant{{Permission: "TerminateTerminalSession", ScopeKind: auth.ScopeKindDeviceGroup, ScopeID: dgX}})

	t.Run("denies terminating a session on an out-of-scope device", func(t *testing.T) {
		sid := openSession(devOut)
		_, err := h.TerminateTerminalSession(terminator, connect.NewRequest(&pm.TerminateTerminalSessionRequest{SessionId: sid, Reason: "x"}))
		require.Error(t, err)
		assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
	})

	t.Run("in-scope device passes scope (fails later only for unconfigured registry)", func(t *testing.T) {
		sid := openSession(devIn)
		// registry/internalHTTPClient are nil in the test handler, so an in-scope
		// session proceeds past the scope gate and then fails Unavailable — never
		// PermissionDenied.
		_, err := h.TerminateTerminalSession(terminator, connect.NewRequest(&pm.TerminateTerminalSessionRequest{SessionId: sid, Reason: "x"}))
		if err != nil {
			assert.NotEqual(t, connect.CodePermissionDenied, connect.CodeOf(err))
		}
	})
}

// ListActiveTerminalSessions filters the merged session list to devices in the
// caller's ListActiveTerminalSessions device-group scope.
func TestScopedSessions_FiltersByDeviceScope(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h, _ := newTerminalHandler(t, st)

	actor := testutil.CreateTestUser(t, st, testutil.NewID()+"@a.com", "pass", "admin")
	dgX := testutil.CreateTestDeviceGroup(t, st, actor, "Plant X")
	devIn := testutil.CreateTestDevice(t, st, "in-scope")
	devOut := testutil.CreateTestDevice(t, st, "out-of-scope")
	testutil.AddDeviceToTestGroup(t, st, actor, dgX, devIn)

	sessions := []*pm.TerminalSessionInfo{
		{SessionId: "s-in", DeviceId: devIn},
		{SessionId: "s-out", DeviceId: devOut},
	}

	scoped := testutil.AuthContextScoped(actor, "u@test.com",
		[]string{"ListActiveTerminalSessions"},
		[]auth.ScopedGrant{{Permission: "ListActiveTerminalSessions", ScopeKind: auth.ScopeKindDeviceGroup, ScopeID: dgX}})

	t.Run("scoped caller sees only in-scope sessions", func(t *testing.T) {
		got, err := h.ScopedSessionsForTest(scoped, sessions)
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, "s-in", got[0].SessionId)
	})

	t.Run("global caller sees all sessions", func(t *testing.T) {
		global := testutil.AuthContextScoped(actor, "u@test.com",
			[]string{"ListActiveTerminalSessions"},
			[]auth.ScopedGrant{{Permission: "ListActiveTerminalSessions"}})
		got, err := h.ScopedSessionsForTest(global, sessions)
		require.NoError(t, err)
		assert.Len(t, got, 2)
	})

	t.Run("unauthenticated caller sees nothing (fail closed)", func(t *testing.T) {
		got, err := h.ScopedSessionsForTest(context.Background(), sessions)
		require.NoError(t, err)
		assert.Empty(t, got)
	})
}
