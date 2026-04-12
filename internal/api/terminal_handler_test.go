package api_test

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/gateway/registry"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/terminal"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// setLinuxUsername appends the UserLinuxUsernameChanged event so the
// projection picks up the linux_username for tests that need
// StartTerminal to resolve a TTY user.
func setLinuxUsername(t *testing.T, st *store.Store, userID, linuxUsername string) {
	t.Helper()
	err := st.AppendEvent(context.Background(), store.Event{
		StreamType: "user",
		StreamID:   userID,
		EventType:  "UserLinuxUsernameChanged",
		Data:       map[string]any{"linux_username": linuxUsername},
		ActorType:  "system",
		ActorID:    "test",
	})
	require.NoError(t, err)
}

// newTerminalHandler builds a TerminalHandler over the given store and
// a fresh in-memory terminal token store. Returned alongside the token
// store so individual tests can poke at it directly when they need to
// assert mint/revoke side effects.
func newTerminalHandler(t *testing.T, st *store.Store) (*api.TerminalHandler, *terminal.TokenStore) {
	t.Helper()
	tokenStore := terminal.NewTokenStore(terminal.NewFakeBackend(nil))
	// nil registry → single-gateway fallback path using the static URL.
	h := api.NewTerminalHandler(st, tokenStore, nil, "wss://gateway.example.com/terminal", slog.Default())
	return h, tokenStore
}

// authedCtx returns a context with a UserContext attached, mimicking
// what AuthInterceptor produces in the real request pipeline.
func authedCtx(userID string) context.Context {
	return auth.WithUser(context.Background(), &auth.UserContext{ID: userID})
}

func TestStartTerminal_HappyPath(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h, tokenStore := newTerminalHandler(t, st)

	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	setLinuxUsername(t, st, userID, "alice")
	deviceID := testutil.CreateTestDevice(t, st, "host-1")
	testutil.AssignDeviceToUser(t, st, userID, deviceID, userID)

	resp, err := h.StartTerminal(authedCtx(userID), connect.NewRequest(&pm.StartTerminalRequest{
		DeviceId: deviceID,
		Cols:     100,
		Rows:     30,
	}))
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Msg.SessionId)
	assert.NotEmpty(t, resp.Msg.SessionToken)
	assert.Equal(t, "wss://gateway.example.com/terminal", resp.Msg.GatewayUrl)
	assert.Equal(t, "pm-tty-alice", resp.Msg.TtyUser)
	assert.NotNil(t, resp.Msg.ExpiresAt)

	// Token must be stored under the returned session id with matching
	// metadata, and must validate against the bearer token returned to
	// the client.
	stored, err := tokenStore.Validate(context.Background(), resp.Msg.SessionId, resp.Msg.SessionToken)
	require.NoError(t, err)
	assert.Equal(t, userID, stored.UserID)
	assert.Equal(t, deviceID, stored.DeviceID)
	assert.Equal(t, "pm-tty-alice", stored.TtyUser)
	assert.Equal(t, uint32(100), stored.Cols)
	assert.Equal(t, uint32(30), stored.Rows)
}

func TestStartTerminal_DefaultsWhenColsRowsZero(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h, tokenStore := newTerminalHandler(t, st)

	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	setLinuxUsername(t, st, userID, "bob")
	deviceID := testutil.CreateTestDevice(t, st, "host-2")
	testutil.AssignDeviceToUser(t, st, userID, deviceID, userID)

	resp, err := h.StartTerminal(authedCtx(userID), connect.NewRequest(&pm.StartTerminalRequest{
		DeviceId: deviceID,
		// no Cols/Rows
	}))
	require.NoError(t, err)

	stored, err := tokenStore.Lookup(context.Background(), resp.Msg.SessionId)
	require.NoError(t, err)
	assert.Equal(t, uint32(80), stored.Cols)
	assert.Equal(t, uint32(24), stored.Rows)
}

func TestStartTerminal_NoLinuxUsername(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h, _ := newTerminalHandler(t, st)

	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	// Intentionally NOT calling setLinuxUsername.
	deviceID := testutil.CreateTestDevice(t, st, "host-3")
	testutil.AssignDeviceToUser(t, st, userID, deviceID, userID)

	_, err := h.StartTerminal(authedCtx(userID), connect.NewRequest(&pm.StartTerminalRequest{
		DeviceId: deviceID,
	}))
	require.Error(t, err)
	var connectErr *connect.Error
	require.True(t, errors.As(err, &connectErr))
	assert.Equal(t, connect.CodeFailedPrecondition, connectErr.Code())
}

func TestStartTerminal_DeviceNotFound(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h, _ := newTerminalHandler(t, st)

	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	setLinuxUsername(t, st, userID, "alice")

	_, err := h.StartTerminal(authedCtx(userID), connect.NewRequest(&pm.StartTerminalRequest{
		DeviceId: "non-existent-device",
	}))
	require.Error(t, err)
	var connectErr *connect.Error
	require.True(t, errors.As(err, &connectErr))
	assert.Equal(t, connect.CodeNotFound, connectErr.Code())
}

func TestStartTerminal_NotAuthenticated(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h, _ := newTerminalHandler(t, st)

	deviceID := testutil.CreateTestDevice(t, st, "host-4")

	_, err := h.StartTerminal(context.Background(), connect.NewRequest(&pm.StartTerminalRequest{
		DeviceId: deviceID,
	}))
	require.Error(t, err)
	var connectErr *connect.Error
	require.True(t, errors.As(err, &connectErr))
	assert.Equal(t, connect.CodeUnauthenticated, connectErr.Code())
}

func TestStopTerminal_OwnerCanStop(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h, tokenStore := newTerminalHandler(t, st)

	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	setLinuxUsername(t, st, userID, "alice")
	deviceID := testutil.CreateTestDevice(t, st, "host-5")
	testutil.AssignDeviceToUser(t, st, userID, deviceID, userID)

	startResp, err := h.StartTerminal(authedCtx(userID), connect.NewRequest(&pm.StartTerminalRequest{
		DeviceId: deviceID,
	}))
	require.NoError(t, err)

	_, err = h.StopTerminal(authedCtx(userID), connect.NewRequest(&pm.StopTerminalRequest{
		SessionId: startResp.Msg.SessionId,
	}))
	require.NoError(t, err)

	// Session should be gone from the store.
	_, lookupErr := tokenStore.Lookup(context.Background(), startResp.Msg.SessionId)
	assert.ErrorIs(t, lookupErr, terminal.ErrTokenNotFound)
}

func TestStopTerminal_OtherUserCannotStop(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h, tokenStore := newTerminalHandler(t, st)

	ownerID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	setLinuxUsername(t, st, ownerID, "alice")
	otherID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	setLinuxUsername(t, st, otherID, "bob")
	deviceID := testutil.CreateTestDevice(t, st, "host-6")
	testutil.AssignDeviceToUser(t, st, ownerID, deviceID, ownerID)

	startResp, err := h.StartTerminal(authedCtx(ownerID), connect.NewRequest(&pm.StartTerminalRequest{
		DeviceId: deviceID,
	}))
	require.NoError(t, err)

	_, err = h.StopTerminal(authedCtx(otherID), connect.NewRequest(&pm.StopTerminalRequest{
		SessionId: startResp.Msg.SessionId,
	}))
	require.Error(t, err)
	var connectErr *connect.Error
	require.True(t, errors.As(err, &connectErr))
	assert.Equal(t, connect.CodePermissionDenied, connectErr.Code())

	// Session must still be live — the rejected stop must not have
	// revoked the token.
	_, lookupErr := tokenStore.Lookup(context.Background(), startResp.Msg.SessionId)
	require.NoError(t, lookupErr)

	// TODO: add a test covering the admin TerminateTerminalSession path once
	// that RPC is implemented (requires gateway-side session inventory and
	// GatewayService fan-out — tracked in a follow-up PR).
}

func TestStopTerminal_UnknownSessionIsIdempotent(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h, _ := newTerminalHandler(t, st)

	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")

	resp, err := h.StopTerminal(authedCtx(userID), connect.NewRequest(&pm.StopTerminalRequest{
		SessionId: "no-such-session",
	}))
	require.NoError(t, err)
	require.NotNil(t, resp)
}

func TestStopTerminal_NotAuthenticated(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h, _ := newTerminalHandler(t, st)

	_, err := h.StopTerminal(context.Background(), connect.NewRequest(&pm.StopTerminalRequest{
		SessionId: "any",
	}))
	require.Error(t, err)
	var connectErr *connect.Error
	require.True(t, errors.As(err, &connectErr))
	assert.Equal(t, connect.CodeUnauthenticated, connectErr.Code())
}

func TestGatewayBaseURL_StripsTokenAndTrailingSlash(t *testing.T) {
	cases := map[string]string{
		"":                                       "",
		"wss://gw/terminal":                      "wss://gw/terminal",
		"wss://gw/terminal/":                     "wss://gw/terminal",
		"wss://gw/terminal?token=abc":            "wss://gw/terminal",
		"wss://gw/terminal?token=abc&extra=1":    "wss://gw/terminal",
		"wss://gw/terminal#frag":                 "wss://gw/terminal",
		// Userinfo credentials must be stripped.
		"wss://admin:secret@gw/terminal":         "wss://gw/terminal",
		"wss://user@gw/terminal?token=abc":       "wss://gw/terminal",
	}
	for in, want := range cases {
		got := api.GatewayBaseURL(in)
		if got != want {
			t.Errorf("GatewayBaseURL(%q) = %q, want %q", in, got, want)
		}
	}
	// The resulting base must contain neither '?', '#', nor '@'.
	for in := range cases {
		out := api.GatewayBaseURL(in)
		if strings.ContainsAny(out, "?#@") {
			t.Errorf("GatewayBaseURL(%q) leaked query/fragment/userinfo: %q", in, out)
		}
	}
}

// TestStartTerminal_RegistryRouting verifies that when a registry is
// configured, StartTerminal resolves the gateway URL dynamically from
// the device→gateway→URL chain instead of using the static fallback.
func TestStartTerminal_RegistryRouting(t *testing.T) {
	st := testutil.SetupPostgres(t)
	tokenStore := terminal.NewTokenStore(terminal.NewFakeBackend(nil))
	backend := registry.NewFakeBackend(nil)
	reg := registry.New(backend, slog.Default())
	// Empty fallback so we know the returned URL came from the registry.
	h := api.NewTerminalHandler(st, tokenStore, reg, "", slog.Default())

	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	setLinuxUsername(t, st, userID, "alice")
	deviceID := testutil.CreateTestDevice(t, st, "host-reg")

	// Simulate the gateway publishing its registration + the device mapping.
	ctx := context.Background()
	require.NoError(t, reg.AttachDevice(ctx, deviceID, "gw-42", registry.DefaultDeviceTTL))
	stop, err := reg.RegisterGateway(ctx, "gw-42", "wss://gw-42.gateway.example.com/terminal", registry.DefaultGatewayTTL, registry.DefaultGatewayRefreshInterval)
	require.NoError(t, err)
	defer stop()

	resp, err := h.StartTerminal(authedCtx(userID), connect.NewRequest(&pm.StartTerminalRequest{
		DeviceId: deviceID,
	}))
	require.NoError(t, err)
	assert.Equal(t, "wss://gw-42.gateway.example.com/terminal", resp.Msg.GatewayUrl)
	assert.NotEmpty(t, resp.Msg.SessionId)
	assert.NotEmpty(t, resp.Msg.SessionToken)
}

// TestStartTerminal_RegistryDeviceNotConnected verifies that when the
// device has no device→gateway mapping in the registry (not connected
// to any gateway), StartTerminal returns FailedPrecondition.
func TestStartTerminal_RegistryDeviceNotConnected(t *testing.T) {
	st := testutil.SetupPostgres(t)
	tokenStore := terminal.NewTokenStore(terminal.NewFakeBackend(nil))
	reg := registry.New(registry.NewFakeBackend(nil), slog.Default())
	h := api.NewTerminalHandler(st, tokenStore, reg, "", slog.Default())

	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	setLinuxUsername(t, st, userID, "alice")
	deviceID := testutil.CreateTestDevice(t, st, "host-unreg")

	// No AttachDevice call — device is not connected.
	_, err := h.StartTerminal(authedCtx(userID), connect.NewRequest(&pm.StartTerminalRequest{
		DeviceId: deviceID,
	}))
	require.Error(t, err)
	var connectErr *connect.Error
	require.True(t, errors.As(err, &connectErr))
	assert.Equal(t, connect.CodeFailedPrecondition, connectErr.Code())
}
