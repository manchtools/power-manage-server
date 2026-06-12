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
	"github.com/manchtools/power-manage/server/internal/terminal"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

func TestVerifyDevice_Success(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewInternalHandler(st, testutil.NewEncryptor(t), slog.Default(), api.NoOpSigner{})

	deviceID := testutil.CreateTestDevice(t, st, "verify-host")

	resp, err := h.VerifyDevice(context.Background(), connect.NewRequest(&pm.VerifyDeviceRequest{
		DeviceId: deviceID,
	}))
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestVerifyDevice_NotFound(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewInternalHandler(st, testutil.NewEncryptor(t), slog.Default(), api.NoOpSigner{})

	_, err := h.VerifyDevice(context.Background(), connect.NewRequest(&pm.VerifyDeviceRequest{
		DeviceId: testutil.NewID(),
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
}

func TestVerifyDevice_EmptyID(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewInternalHandler(st, testutil.NewEncryptor(t), slog.Default(), api.NoOpSigner{})

	_, err := h.VerifyDevice(context.Background(), connect.NewRequest(&pm.VerifyDeviceRequest{
		DeviceId: "",
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}

func TestProxySyncActions_EmptyDeviceID(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewInternalHandler(st, testutil.NewEncryptor(t), slog.Default(), api.NoOpSigner{})

	_, err := h.ProxySyncActions(context.Background(), connect.NewRequest(&pm.InternalSyncActionsRequest{
		DeviceId: "",
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}

func TestProxySyncActions_DeviceNotFound(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewInternalHandler(st, testutil.NewEncryptor(t), slog.Default(), api.NoOpSigner{})

	_, err := h.ProxySyncActions(context.Background(), connect.NewRequest(&pm.InternalSyncActionsRequest{
		DeviceId: testutil.NewID(),
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
}

func TestProxySyncActions_NoAssignments(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewInternalHandler(st, testutil.NewEncryptor(t), slog.Default(), api.NoOpSigner{})

	deviceID := testutil.CreateTestDevice(t, st, "sync-host")

	resp, err := h.ProxySyncActions(context.Background(), connect.NewRequest(&pm.InternalSyncActionsRequest{
		DeviceId: deviceID,
	}))
	require.NoError(t, err)
	assert.Empty(t, resp.Msg.StandaloneActions)
}

func TestProxySyncActions_WithAssignment(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewInternalHandler(st, testutil.NewEncryptor(t), slog.Default(), api.NoOpSigner{})

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	deviceID := testutil.CreateTestDevice(t, st, "sync-assigned-host")
	actionID := testutil.CreateTestAction(t, st, adminID, "Sync Action", int(pm.ActionType_ACTION_TYPE_SHELL))

	// Assign action directly to device
	testutil.CreateTestAssignment(t, st, adminID, "action", actionID, "device", deviceID, int(pm.AssignmentMode_ASSIGNMENT_MODE_REQUIRED))

	resp, err := h.ProxySyncActions(context.Background(), connect.NewRequest(&pm.InternalSyncActionsRequest{
		DeviceId: deviceID,
	}))
	require.NoError(t, err)
	assert.Len(t, resp.Msg.StandaloneActions, 1)
	assert.Equal(t, actionID, resp.Msg.StandaloneActions[0].Id.Value)
}

func TestProxySyncActions_UninstallAssignmentForcesAbsent(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewInternalHandler(st, testutil.NewEncryptor(t), slog.Default(), api.NoOpSigner{})

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	deviceID := testutil.CreateTestDevice(t, st, "sync-uninstall-host")
	actionID := testutil.CreateTestAction(t, st, adminID, "Sync Uninstall Action", int(pm.ActionType_ACTION_TYPE_SHELL))

	testutil.CreateTestAssignment(t, st, adminID, "action", actionID, "device", deviceID, uninstallAssignmentMode)

	resp, err := h.ProxySyncActions(context.Background(), connect.NewRequest(&pm.InternalSyncActionsRequest{
		DeviceId: deviceID,
	}))
	require.NoError(t, err)
	require.Len(t, resp.Msg.StandaloneActions, 1)
	assert.Equal(t, actionID, resp.Msg.StandaloneActions[0].Id.Value)
	assert.Equal(t, pm.DesiredState_DESIRED_STATE_ABSENT, resp.Msg.StandaloneActions[0].DesiredState)
}

// Verify that an action set assigned to the device emits one ActionGroup
// rather than appearing on standalone_actions (#45 grouped sync wire).
func TestProxySyncActions_ActionSetAssignmentEmitsGroup(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewInternalHandler(st, testutil.NewEncryptor(t), slog.Default(), api.NoOpSigner{})

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	deviceID := testutil.CreateTestDevice(t, st, "sync-set-host")
	a1 := testutil.CreateTestAction(t, st, adminID, "Set Member 1", int(pm.ActionType_ACTION_TYPE_SHELL))
	a2 := testutil.CreateTestAction(t, st, adminID, "Set Member 2", int(pm.ActionType_ACTION_TYPE_SHELL))
	setID := testutil.CreateTestActionSet(t, st, adminID, "Sync Set")

	testutil.AddActionToTestSet(t, st, adminID, setID, a1, 0)
	testutil.AddActionToTestSet(t, st, adminID, setID, a2, 1)
	testutil.CreateTestAssignment(t, st, adminID, "action_set", setID, "device", deviceID, int(pm.AssignmentMode_ASSIGNMENT_MODE_REQUIRED))

	resp, err := h.ProxySyncActions(context.Background(), connect.NewRequest(&pm.InternalSyncActionsRequest{
		DeviceId: deviceID,
	}))
	require.NoError(t, err)
	assert.Empty(t, resp.Msg.StandaloneActions, "set members ride on grouped_actions, not standalone_actions")
	require.Len(t, resp.Msg.GroupedActions, 1)
	g := resp.Msg.GroupedActions[0]
	assert.Equal(t, "action_set:"+setID, g.SourceLabel)
	require.NotNil(t, g.Schedule, "group must carry the set's schedule")
	require.Len(t, g.Actions, 2)
	assert.Equal(t, a1, g.Actions[0].Id.Value, "members emitted in declared sort_order")
	assert.Equal(t, a2, g.Actions[1].Id.Value)
}

// UNINSTALL on the set's assignment forces every member's desired_state
// to ABSENT regardless of how the action itself was configured.
func TestProxySyncActions_UninstallActionSetForcesAbsent(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewInternalHandler(st, testutil.NewEncryptor(t), slog.Default(), api.NoOpSigner{})

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	deviceID := testutil.CreateTestDevice(t, st, "sync-set-uninstall-host")
	a1 := testutil.CreateTestAction(t, st, adminID, "Doomed", int(pm.ActionType_ACTION_TYPE_SHELL))
	setID := testutil.CreateTestActionSet(t, st, adminID, "Doomed Set")
	testutil.AddActionToTestSet(t, st, adminID, setID, a1, 0)
	testutil.CreateTestAssignment(t, st, adminID, "action_set", setID, "device", deviceID, uninstallAssignmentMode)

	resp, err := h.ProxySyncActions(context.Background(), connect.NewRequest(&pm.InternalSyncActionsRequest{
		DeviceId: deviceID,
	}))
	require.NoError(t, err)
	require.Len(t, resp.Msg.GroupedActions, 1)
	g := resp.Msg.GroupedActions[0]
	require.Len(t, g.Actions, 1)
	assert.Equal(t, pm.DesiredState_DESIRED_STATE_ABSENT, g.Actions[0].DesiredState,
		"UNINSTALL on the container overrides per-action desired_state")
}

func TestProxyStoreLuksKey(t *testing.T) {
	st := testutil.SetupPostgres(t)
	enc := testutil.NewEncryptor(t)
	h := api.NewInternalHandler(st, enc, slog.Default(), api.NoOpSigner{})

	deviceID := testutil.CreateTestDevice(t, st, "luks-store-host")

	resp, err := h.ProxyStoreLuksKey(context.Background(), connect.NewRequest(&pm.InternalStoreLuksKeyRequest{
		DeviceId:       deviceID,
		ActionId:       testutil.NewID(),
		DevicePath:     "/dev/sda1",
		Passphrase:     "super-secret-key",
		RotationReason: pm.RotationReason_ROTATION_REASON_INITIAL,
	}))
	require.NoError(t, err)
	assert.True(t, resp.Msg.Success)
}

func TestProxyStoreLuksKey_MissingFields(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewInternalHandler(st, testutil.NewEncryptor(t), slog.Default(), api.NoOpSigner{})

	_, err := h.ProxyStoreLuksKey(context.Background(), connect.NewRequest(&pm.InternalStoreLuksKeyRequest{
		DeviceId: "",
		ActionId: "",
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}

func TestProxyValidateLuksToken_MissingFields(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewInternalHandler(st, testutil.NewEncryptor(t), slog.Default(), api.NoOpSigner{})

	_, err := h.ProxyValidateLuksToken(context.Background(), connect.NewRequest(&pm.InternalValidateLuksTokenRequest{
		DeviceId: "",
		Token:    "",
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}

func TestProxyGetLuksKey_NotFound(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewInternalHandler(st, testutil.NewEncryptor(t), slog.Default(), api.NoOpSigner{})

	_, err := h.ProxyGetLuksKey(context.Background(), connect.NewRequest(&pm.InternalGetLuksKeyRequest{
		DeviceId: testutil.NewID(),
		ActionId: testutil.NewID(),
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
}

func TestProxyStoreLpsPasswords(t *testing.T) {
	st := testutil.SetupPostgres(t)
	enc := testutil.NewEncryptor(t)
	h := api.NewInternalHandler(st, enc, slog.Default(), api.NoOpSigner{})

	deviceID := testutil.CreateTestDevice(t, st, "lps-host")

	resp, err := h.ProxyStoreLpsPasswords(context.Background(), connect.NewRequest(&pm.InternalStoreLpsPasswordsRequest{
		DeviceId: deviceID,
		ActionId: testutil.NewID(),
		Rotations: []*pm.LpsPasswordRotation{
			{
				Username:  "admin",
				Password:  "new-pass-123",
				RotatedAt: "2026-03-31T12:00:00Z",
				Reason:    pm.RotationReason_ROTATION_REASON_SCHEDULED,
			},
		},
	}))
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestProxyStoreLpsPasswords_MissingFields(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewInternalHandler(st, testutil.NewEncryptor(t), slog.Default(), api.NoOpSigner{})

	_, err := h.ProxyStoreLpsPasswords(context.Background(), connect.NewRequest(&pm.InternalStoreLpsPasswordsRequest{
		DeviceId: "",
		ActionId: "",
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}

// newInternalHandlerWithTokenStore builds an InternalHandler over a
// fresh in-memory token store. Returned alongside the store so tests
// can mint and revoke directly without round-tripping through the
// public StartTerminal handler.
func newInternalHandlerWithTokenStore(t *testing.T) (*api.InternalHandler, *terminal.TokenStore) {
	t.Helper()
	st := testutil.SetupPostgres(t)
	h := api.NewInternalHandler(st, testutil.NewEncryptor(t), slog.Default(), api.NoOpSigner{})
	tokenStore := terminal.NewTokenStore(terminal.NewFakeBackend(nil))
	h.SetTerminalTokenStore(tokenStore)
	return h, tokenStore
}

func TestProxyValidateTerminalToken_HappyPath(t *testing.T) {
	h, tokenStore := newInternalHandlerWithTokenStore(t)

	mintRes, err := tokenStore.Mint(context.Background(), terminal.MintParams{
		UserID:   "user-1",
		DeviceID: "device-1",
		TtyUser:  "pm-tty-alice",
		Cols:     120,
		Rows:     40,
	})
	require.NoError(t, err)

	resp, err := h.ProxyValidateTerminalToken(context.Background(), connect.NewRequest(&pm.InternalValidateTerminalTokenRequest{
		SessionId: mintRes.SessionID,
		Token:     mintRes.Token,
	}))
	require.NoError(t, err)
	assert.Equal(t, "user-1", resp.Msg.UserId)
	assert.Equal(t, "device-1", resp.Msg.DeviceId)
	assert.Equal(t, "pm-tty-alice", resp.Msg.TtyUser)
	assert.Equal(t, uint32(120), resp.Msg.Cols)
	assert.Equal(t, uint32(40), resp.Msg.Rows)
}

func TestProxyValidateTerminalToken_IsSingleUse(t *testing.T) {
	// rc10 contract: a successful validation atomically consumes the
	// token so replays within the TTL fail with Unauthenticated. This
	// blocks the leaked-token replay surface (reverse-proxy access
	// logs capturing query strings, browser history snooping, etc.)
	// without affecting normal operation — the real gateway flow in
	// terminal_bridge.go validates the token exactly once per
	// WebSocket connection and uses the returned metadata for the
	// lifetime of the connection.
	//
	// Supersedes the pre-rc10 TestProxyValidateTerminalToken_DoesNotConsumeToken
	// which asserted the opposite and is exactly the contract the
	// audit flagged as a replay vulnerability.
	h, tokenStore := newInternalHandlerWithTokenStore(t)

	mintRes, err := tokenStore.Mint(context.Background(), terminal.MintParams{
		UserID:   "user-1",
		DeviceID: "device-1",
		TtyUser:  "pm-tty-alice",
	})
	require.NoError(t, err)

	// First validation succeeds and consumes the token.
	_, err = h.ProxyValidateTerminalToken(context.Background(), connect.NewRequest(&pm.InternalValidateTerminalTokenRequest{
		SessionId: mintRes.SessionID,
		Token:     mintRes.Token,
	}))
	require.NoError(t, err, "first validation should succeed")

	// Second validation with the same bearer fails with
	// Unauthenticated — the token is gone.
	_, err = h.ProxyValidateTerminalToken(context.Background(), connect.NewRequest(&pm.InternalValidateTerminalTokenRequest{
		SessionId: mintRes.SessionID,
		Token:     mintRes.Token,
	}))
	require.Error(t, err, "second validation must fail (single-use contract)")
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
}

func TestProxyValidateTerminalToken_UnknownSession(t *testing.T) {
	h, _ := newInternalHandlerWithTokenStore(t)

	// The probe-distinguishability defense protects against an
	// attacker learning whether a session *exists*, not whether the
	// session_id string is a syntactically valid ULID. A malformed
	// session_id is rejected by the validation interceptor + the
	// handler-level Validate() call with InvalidArgument before the
	// token-store lookup, which is the right shape: anyone can tell
	// a malformed input from "no session here" without probing. Use
	// a valid-format-but-unminted ULID so the request reaches the
	// token check and the comparison below pins the equal-message
	// contract for the cases where it actually matters.
	unknownSessionID := testutil.NewID()
	_, err := h.ProxyValidateTerminalToken(context.Background(), connect.NewRequest(&pm.InternalValidateTerminalTokenRequest{
		SessionId: unknownSessionID,
		Token:     "anything",
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
	unknownMsg := err.Error()

	// Mismatched and unknown must produce the SAME gRPC code AND the
	// SAME error message so a forgery probe cannot distinguish them.
	// The log messages differ (Warn vs Debug) but the wire response
	// is identical.
	h2, tokenStore := newInternalHandlerWithTokenStore(t)
	mintRes, err := tokenStore.Mint(context.Background(), terminal.MintParams{
		UserID:   "user-1",
		DeviceID: "device-1",
		TtyUser:  "pm-tty-alice",
	})
	require.NoError(t, err)

	_, err = h2.ProxyValidateTerminalToken(context.Background(), connect.NewRequest(&pm.InternalValidateTerminalTokenRequest{
		SessionId: mintRes.SessionID,
		Token:     "wrong-token",
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
	mismatchMsg := err.Error()

	assert.Equal(t, unknownMsg, mismatchMsg,
		"unknown and mismatched errors must have the same message to prevent probe distinguishability")
}

func TestProxyValidateTerminalToken_RevokedToken(t *testing.T) {
	h, tokenStore := newInternalHandlerWithTokenStore(t)

	mintRes, err := tokenStore.Mint(context.Background(), terminal.MintParams{
		UserID:   "user-1",
		DeviceID: "device-1",
		TtyUser:  "pm-tty-alice",
	})
	require.NoError(t, err)
	require.NoError(t, tokenStore.Revoke(context.Background(), mintRes.SessionID))

	_, err = h.ProxyValidateTerminalToken(context.Background(), connect.NewRequest(&pm.InternalValidateTerminalTokenRequest{
		SessionId: mintRes.SessionID,
		Token:     mintRes.Token,
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
}

func TestProxyValidateTerminalToken_MissingFields(t *testing.T) {
	h, _ := newInternalHandlerWithTokenStore(t)

	cases := []*pm.InternalValidateTerminalTokenRequest{
		{},
		{SessionId: "01ABC"},
		{Token: "tok"},
	}
	for _, req := range cases {
		_, err := h.ProxyValidateTerminalToken(context.Background(), connect.NewRequest(req))
		require.Error(t, err)
		assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
	}
}

func TestProxyValidateTerminalToken_StoreNotConfigured(t *testing.T) {
	// When SetTerminalTokenStore was never called (e.g. control
	// instance running without TerminalGatewayURL), the RPC must
	// return Unavailable so the gateway can degrade gracefully
	// instead of returning a confusing 'method not found'.
	//
	// The session_id must be a syntactically valid ULID — the new
	// boundary validation rejects malformed inputs with
	// InvalidArgument before the store-not-configured check fires,
	// which would hide the behavior we want to pin. Use a freshly
	// minted ULID here.
	st := testutil.SetupPostgres(t)
	h := api.NewInternalHandler(st, testutil.NewEncryptor(t), slog.Default(), api.NoOpSigner{})

	_, err := h.ProxyValidateTerminalToken(context.Background(), connect.NewRequest(&pm.InternalValidateTerminalTokenRequest{
		SessionId: testutil.NewID(),
		Token:     "tok",
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeUnavailable, connect.CodeOf(err))
}
