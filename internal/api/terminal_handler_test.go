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

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/terminal"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// errorCode pulls the structured error code (pm.ErrorDetail.Code)
// off a connect.Error. The SDK + web client both switch on this
// field, so it's the canonical contract test for the rc11 #79
// terminal error split — message substring assertions are a secondary
// hint check that's free to evolve with copy edits.
func errorCode(t *testing.T, e *connect.Error) string {
	t.Helper()
	require.NotEmpty(t, e.Details(), "connect error has no structured details — apiErrorCtx wiring broken?")
	val, err := e.Details()[0].Value()
	require.NoError(t, err, "decode ErrorDetail proto")
	detail, ok := val.(*pm.ErrorDetail)
	require.True(t, ok, "first detail is not pm.ErrorDetail (got %T)", val)
	return detail.Code
}

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
	h := api.NewTerminalHandler(st, tokenStore, "wss://control.example.com/terminal", slog.Default())
	// Default transport: device connected, stop succeeds and finds the session.
	// Tests that need the offline or indeterminate paths override this.
	h.SetTerminalTransport(
		func(context.Context) ([]*pm.TerminalSessionInfo, error) { return nil, nil },
		func(context.Context, string, string, string) (bool, error) { return true, nil },
		func(string) bool { return true },
	)
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
	assert.Equal(t, "wss://control.example.com/terminal", resp.Msg.TerminalUrl)
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
		// Valid-format ULID that isn't in the devices_projection.
		DeviceId: testutil.NewID(),
	}))
	require.Error(t, err)
	var connectErr *connect.Error
	require.True(t, errors.As(err, &connectErr))
	assert.Equal(t, connect.CodeNotFound, connectErr.Code())
}

// TestStartTerminal_AdminUnassigned covers the bulk-enrollment case
// surfaced by manchtools/power-manage-server#85: a device that no
// user is assigned to (no direct assignment, no group membership)
// must still be reachable by an admin who holds the unrestricted
// StartTerminal permission. The previous hardcoded
// `filterUserID := userCtx.ID` collapsed admin and :assigned users
// into the same scope and surfaced as "device not found" for any
// device the admin hadn't explicitly assigned to themselves.
func TestStartTerminal_AdminUnassigned(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h, _ := newTerminalHandler(t, st)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	setLinuxUsername(t, st, adminID, "alice")
	deviceID := testutil.CreateTestDevice(t, st, "unassigned-host")
	// Deliberately no AssignDeviceToUser call — the device is
	// ownerless / unassigned, the bulk-enrollment scenario.

	resp, err := h.StartTerminal(testutil.AdminContext(adminID), connect.NewRequest(&pm.StartTerminalRequest{
		DeviceId: deviceID,
	}))
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Msg.SessionId)
	assert.Equal(t, "pm-tty-alice", resp.Msg.TtyUser)
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

	// Audit L4: a non-owner gets the SAME idempotent empty OK an unknown session
	// returns (see TestStopTerminal_UnknownSessionIsIdempotent), never
	// PermissionDenied — so the owner-vs-not distinction can't be used as an
	// existence oracle for the opaque session id.
	// Red check: this asserted CodePermissionDenied before the fix.
	resp, err := h.StopTerminal(authedCtx(otherID), connect.NewRequest(&pm.StopTerminalRequest{
		SessionId: startResp.Msg.SessionId,
	}))
	require.NoError(t, err, "a non-owner must get the same idempotent OK as a missing session, not PermissionDenied (existence oracle)")
	require.NotNil(t, resp)

	// Session must still be live — a non-owner's request must NOT revoke the
	// token; only the owner's stop mutates the session.
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
		// Valid-format ULID that no session has minted.
		SessionId: testutil.NewID(),
	}))
	require.NoError(t, err)
	require.NotNil(t, resp)
}

func TestStopTerminal_NotAuthenticated(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h, _ := newTerminalHandler(t, st)

	_, err := h.StopTerminal(context.Background(), connect.NewRequest(&pm.StopTerminalRequest{
		// Valid-format ULID — the test asserts the auth gate fires
		// before any session-store lookup, so the request only needs
		// to pass boundary validation. A malformed value would short-
		// circuit at InvalidArgument and hide the auth check we're
		// pinning.
		SessionId: testutil.NewID(),
	}))
	require.Error(t, err)
	var connectErr *connect.Error
	require.True(t, errors.As(err, &connectErr))
	assert.Equal(t, connect.CodeUnauthenticated, connectErr.Code())
}

// TestTerminateTerminalSession_NotAuthenticated is a regression lock
// for the rc7 rework of the silent actor-ID fallback. Earlier revisions
// of this handler ran a closure that attributed the audit event to
// the literal string "system" when no user was present in ctx — which
// hid any future auth-middleware misconfiguration behind a valid-looking
// audit trail and broke the "every event has a real actor" invariant.
// The handler now returns CodeUnauthenticated at the boundary; this
// test asserts a bare context is rejected before any admin fan-out or
// event-append work runs.
func TestTerminateTerminalSession_NotAuthenticated(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h, _ := newTerminalHandler(t, st)

	_, err := h.TerminateTerminalSession(context.Background(), connect.NewRequest(&pm.TerminateTerminalSessionRequest{
		// Valid-format ULID for the same reason as
		// TestStopTerminal_NotAuthenticated above — the test is
		// about the auth gate firing first, not the session lookup.
		SessionId: testutil.NewID(),
		Reason:    "test",
	}))
	require.Error(t, err)
	var connectErr *connect.Error
	require.True(t, errors.As(err, &connectErr))
	assert.Equal(t, connect.CodeUnauthenticated, connectErr.Code())
}

func TestTerminalBaseURL_StripsTokenAndTrailingSlash(t *testing.T) {
	cases := map[string]string{
		"":                                    "",
		"wss://gw/terminal":                   "wss://gw/terminal",
		"wss://gw/terminal/":                  "wss://gw/terminal",
		"wss://gw/terminal?token=abc":         "wss://gw/terminal",
		"wss://gw/terminal?token=abc&extra=1": "wss://gw/terminal",
		"wss://gw/terminal#frag":              "wss://gw/terminal",
		// Userinfo credentials must be stripped.
		"wss://admin:secret@gw/terminal":   "wss://gw/terminal",
		"wss://user@gw/terminal?token=abc": "wss://gw/terminal",
	}
	for in, want := range cases {
		got := api.TerminalBaseURL(in)
		if got != want {
			t.Errorf("GatewayBaseURL(%q) = %q, want %q", in, got, want)
		}
	}
	// The resulting base must contain neither '?', '#', nor '@'.
	for in := range cases {
		out := api.TerminalBaseURL(in)
		if strings.ContainsAny(out, "?#@") {
			t.Errorf("GatewayBaseURL(%q) leaked query/fragment/userinfo: %q", in, out)
		}
	}
}
