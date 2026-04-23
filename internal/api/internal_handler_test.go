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
	h := api.NewInternalHandler(st, testutil.NewEncryptor(t), slog.Default())

	deviceID := testutil.CreateTestDevice(t, st, "verify-host")

	resp, err := h.VerifyDevice(context.Background(), connect.NewRequest(&pm.VerifyDeviceRequest{
		DeviceId: deviceID,
	}))
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestVerifyDevice_NotFound(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewInternalHandler(st, testutil.NewEncryptor(t), slog.Default())

	_, err := h.VerifyDevice(context.Background(), connect.NewRequest(&pm.VerifyDeviceRequest{
		DeviceId: testutil.NewID(),
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
}

func TestVerifyDevice_EmptyID(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewInternalHandler(st, testutil.NewEncryptor(t), slog.Default())

	_, err := h.VerifyDevice(context.Background(), connect.NewRequest(&pm.VerifyDeviceRequest{
		DeviceId: "",
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}

func TestProxySyncActions_EmptyDeviceID(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewInternalHandler(st, testutil.NewEncryptor(t), slog.Default())

	_, err := h.ProxySyncActions(context.Background(), connect.NewRequest(&pm.InternalSyncActionsRequest{
		DeviceId: "",
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}

func TestProxySyncActions_DeviceNotFound(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewInternalHandler(st, testutil.NewEncryptor(t), slog.Default())

	_, err := h.ProxySyncActions(context.Background(), connect.NewRequest(&pm.InternalSyncActionsRequest{
		DeviceId: testutil.NewID(),
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
}

func TestProxySyncActions_NoAssignments(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewInternalHandler(st, testutil.NewEncryptor(t), slog.Default())

	deviceID := testutil.CreateTestDevice(t, st, "sync-host")

	resp, err := h.ProxySyncActions(context.Background(), connect.NewRequest(&pm.InternalSyncActionsRequest{
		DeviceId: deviceID,
	}))
	require.NoError(t, err)
	assert.Empty(t, resp.Msg.Actions)
}

func TestProxySyncActions_WithAssignment(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewInternalHandler(st, testutil.NewEncryptor(t), slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	deviceID := testutil.CreateTestDevice(t, st, "sync-assigned-host")
	actionID := testutil.CreateTestAction(t, st, adminID, "Sync Action", int(pm.ActionType_ACTION_TYPE_SHELL))

	// Assign action directly to device
	testutil.CreateTestAssignment(t, st, adminID, "action", actionID, "device", deviceID, int(pm.AssignmentMode_ASSIGNMENT_MODE_REQUIRED))

	resp, err := h.ProxySyncActions(context.Background(), connect.NewRequest(&pm.InternalSyncActionsRequest{
		DeviceId: deviceID,
	}))
	require.NoError(t, err)
	assert.Len(t, resp.Msg.Actions, 1)
	assert.Equal(t, actionID, resp.Msg.Actions[0].Id.Value)
}

func TestProxyStoreLuksKey(t *testing.T) {
	st := testutil.SetupPostgres(t)
	enc := testutil.NewEncryptor(t)
	h := api.NewInternalHandler(st, enc, slog.Default())

	deviceID := testutil.CreateTestDevice(t, st, "luks-store-host")

	resp, err := h.ProxyStoreLuksKey(context.Background(), connect.NewRequest(&pm.InternalStoreLuksKeyRequest{
		DeviceId:       deviceID,
		ActionId:       testutil.NewID(),
		DevicePath:     "/dev/sda1",
		Passphrase:     "super-secret-key",
		RotationReason: "initial",
	}))
	require.NoError(t, err)
	assert.True(t, resp.Msg.Success)
}

func TestProxyStoreLuksKey_MissingFields(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewInternalHandler(st, testutil.NewEncryptor(t), slog.Default())

	_, err := h.ProxyStoreLuksKey(context.Background(), connect.NewRequest(&pm.InternalStoreLuksKeyRequest{
		DeviceId: "",
		ActionId: "",
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}

func TestProxyValidateLuksToken_MissingFields(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewInternalHandler(st, testutil.NewEncryptor(t), slog.Default())

	_, err := h.ProxyValidateLuksToken(context.Background(), connect.NewRequest(&pm.InternalValidateLuksTokenRequest{
		DeviceId: "",
		Token:    "",
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}

func TestProxyGetLuksKey_NotFound(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewInternalHandler(st, testutil.NewEncryptor(t), slog.Default())

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
	h := api.NewInternalHandler(st, enc, slog.Default())

	deviceID := testutil.CreateTestDevice(t, st, "lps-host")

	resp, err := h.ProxyStoreLpsPasswords(context.Background(), connect.NewRequest(&pm.InternalStoreLpsPasswordsRequest{
		DeviceId: deviceID,
		ActionId: testutil.NewID(),
		Rotations: []*pm.LpsPasswordRotation{
			{
				Username:  "admin",
				Password:  "new-pass-123",
				RotatedAt: "2026-03-31T12:00:00Z",
				Reason:    "scheduled",
			},
		},
	}))
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestProxyStoreLpsPasswords_MissingFields(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewInternalHandler(st, testutil.NewEncryptor(t), slog.Default())

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
	h := api.NewInternalHandler(st, testutil.NewEncryptor(t), slog.Default())
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

	_, err := h.ProxyValidateTerminalToken(context.Background(), connect.NewRequest(&pm.InternalValidateTerminalTokenRequest{
		SessionId: "no-such-session",
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
	st := testutil.SetupPostgres(t)
	h := api.NewInternalHandler(st, testutil.NewEncryptor(t), slog.Default())

	_, err := h.ProxyValidateTerminalToken(context.Background(), connect.NewRequest(&pm.InternalValidateTerminalTokenRequest{
		SessionId: "01ABC",
		Token:     "tok",
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeUnavailable, connect.CodeOf(err))
}
