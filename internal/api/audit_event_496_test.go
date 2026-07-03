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
	db "github.com/manchtools/power-manage/server/internal/store/generated"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// countDeviceEventsOfType counts events of a given type on a device stream —
// the audit trail the #496 RPCs must leave (a device stream also carries the
// DeviceRegistered bootstrap event, so we filter by type).
func countDeviceEventsOfType(t *testing.T, st *store.Store, deviceID, eventType string) int {
	t.Helper()
	events, err := st.Queries().LoadStream(context.Background(), db.LoadStreamParams{
		StreamType: "device",
		StreamID:   deviceID,
	})
	require.NoError(t, err)
	n := 0
	for _, e := range events {
		if e.EventType == eventType {
			n++
		}
	}
	return n
}

func countUserEventsOfType(t *testing.T, st *store.Store, userID, eventType string) int {
	t.Helper()
	events, err := st.Queries().LoadStream(context.Background(), db.LoadStreamParams{
		StreamType: "user",
		StreamID:   userID,
	})
	require.NoError(t, err)
	n := 0
	for _, e := range events {
		if e.EventType == eventType {
			n++
		}
	}
	return n
}

// --- DispatchOSQuery → OSQueryDispatched -----------------------------------

func TestDispatchOSQuery_AppendsAuditEvent(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewOSQueryHandler(st, slog.Default(), api.NoOpSigner{})
	h.SetTaskQueueClient(&api.NoOpEnqueuer{})
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)
	deviceID := testutil.CreateTestDevice(t, st, "osq-audit-host")

	_, err := h.DispatchOSQuery(ctx, connect.NewRequest(&pm.DispatchOSQueryRequest{
		DeviceId: deviceID, Table: "processes",
	}))
	require.NoError(t, err)
	assert.Equal(t, 1, countDeviceEventsOfType(t, st, deviceID, "OSQueryDispatched"),
		"a successful dispatch appends exactly one audit event")
}

func TestDispatchOSQuery_RejectedAppendsNoEvent(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewOSQueryHandler(st, slog.Default(), api.NoOpSigner{})
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)
	missing := testutil.NewID()

	_, err := h.DispatchOSQuery(ctx, connect.NewRequest(&pm.DispatchOSQueryRequest{
		DeviceId: missing, Table: "processes",
	}))
	require.Error(t, err)
	assert.Equal(t, 0, countDeviceEventsOfType(t, st, missing, "OSQueryDispatched"),
		"a rejected dispatch appends no audit event")
}

// --- QueryDeviceLogs → DeviceLogsQueried -----------------------------------

func TestQueryDeviceLogs_AppendsAuditEvent(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewLogsHandler(st, slog.Default(), api.NoOpSigner{})
	h.SetTaskQueueClient(&api.NoOpEnqueuer{})
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)
	deviceID := testutil.CreateTestDevice(t, st, "logs-audit-host")

	_, err := h.QueryDeviceLogs(ctx, connect.NewRequest(&pm.QueryDeviceLogsRequest{
		DeviceId: deviceID, Unit: "sshd.service",
	}))
	require.NoError(t, err)
	assert.Equal(t, 1, countDeviceEventsOfType(t, st, deviceID, "DeviceLogsQueried"))
}

func TestQueryDeviceLogs_RejectedAppendsNoEvent(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewLogsHandler(st, slog.Default(), api.NoOpSigner{})
	h.SetTaskQueueClient(&api.NoOpEnqueuer{})
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)
	missing := testutil.NewID()

	_, err := h.QueryDeviceLogs(ctx, connect.NewRequest(&pm.QueryDeviceLogsRequest{
		DeviceId: missing,
	}))
	require.Error(t, err)
	assert.Equal(t, 0, countDeviceEventsOfType(t, st, missing, "DeviceLogsQueried"))
}

// --- RefreshDeviceInventory → DeviceInventoryRefreshRequested --------------

func TestRefreshDeviceInventory_AppendsAuditEvent(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewOSQueryHandler(st, slog.Default(), api.NoOpSigner{})
	h.SetTaskQueueClient(&api.NoOpEnqueuer{})
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)
	deviceID := testutil.CreateTestDevice(t, st, "inv-audit-host")

	_, err := h.RefreshDeviceInventory(ctx, connect.NewRequest(&pm.RefreshDeviceInventoryRequest{
		DeviceId: deviceID,
	}))
	require.NoError(t, err)
	assert.Equal(t, 1, countDeviceEventsOfType(t, st, deviceID, "DeviceInventoryRefreshRequested"))
}

func TestRefreshDeviceInventory_RejectedAppendsNoEvent(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewOSQueryHandler(st, slog.Default(), api.NoOpSigner{})
	h.SetTaskQueueClient(&api.NoOpEnqueuer{})
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)
	missing := testutil.NewID()

	_, err := h.RefreshDeviceInventory(ctx, connect.NewRequest(&pm.RefreshDeviceInventoryRequest{
		DeviceId: missing,
	}))
	require.Error(t, err)
	assert.Equal(t, 0, countDeviceEventsOfType(t, st, missing, "DeviceInventoryRefreshRequested"))
}

// --- Logout → UserLoggedOut ------------------------------------------------

func TestLogout_AppendsAuditEvent(t *testing.T) {
	st := testutil.SetupPostgres(t)
	jwtMgr := testutil.NewJWTManager()
	h := api.NewAuthHandler(st, slog.Default(), jwtMgr, true)
	email := testutil.NewID() + "@test.com"
	userID := testutil.CreateTestUser(t, st, email, "correct-password", "user")

	login, err := h.Login(context.Background(), connect.NewRequest(&pm.LoginRequest{
		Email: email, Password: "correct-password",
	}))
	require.NoError(t, err)

	_, err = h.Logout(context.Background(), connect.NewRequest(&pm.LogoutRequest{
		RefreshToken: login.Msg.RefreshToken,
	}))
	require.NoError(t, err)
	assert.Equal(t, 1, countUserEventsOfType(t, st, userID, "UserLoggedOut"),
		"a logout with a valid refresh token appends one UserLoggedOut")
}

func TestLogout_InvalidTokenAppendsNoEvent(t *testing.T) {
	st := testutil.SetupPostgres(t)
	jwtMgr := testutil.NewJWTManager()
	h := api.NewAuthHandler(st, slog.Default(), jwtMgr, true)
	email := testutil.NewID() + "@test.com"
	userID := testutil.CreateTestUser(t, st, email, "correct-password", "user")

	// A logout with an unparseable refresh token revokes nothing (no valid
	// jti) and therefore audits nothing — Logout still returns OK (it is
	// idempotent), so the audit-absence is the meaningful assertion.
	_, err := h.Logout(context.Background(), connect.NewRequest(&pm.LogoutRequest{
		RefreshToken: "not-a-valid-token",
	}))
	require.NoError(t, err)
	assert.Equal(t, 0, countUserEventsOfType(t, st, userID, "UserLoggedOut"))
}

// --- RefreshToken → UserSessionRefreshed -----------------------------------

func TestRefreshToken_AppendsAuditEvent(t *testing.T) {
	st := testutil.SetupPostgres(t)
	jwtMgr := testutil.NewJWTManager()
	h := api.NewAuthHandler(st, slog.Default(), jwtMgr, true)
	email := testutil.NewID() + "@test.com"
	userID := testutil.CreateTestUser(t, st, email, "correct-password", "user")

	login, err := h.Login(context.Background(), connect.NewRequest(&pm.LoginRequest{
		Email: email, Password: "correct-password",
	}))
	require.NoError(t, err)

	_, err = h.RefreshToken(context.Background(), connect.NewRequest(&pm.RefreshTokenRequest{
		RefreshToken: login.Msg.RefreshToken,
	}))
	require.NoError(t, err)
	assert.Equal(t, 1, countUserEventsOfType(t, st, userID, "UserSessionRefreshed"),
		"a successful refresh appends one UserSessionRefreshed")
}

func TestRefreshToken_RejectedAppendsNoEvent(t *testing.T) {
	st := testutil.SetupPostgres(t)
	jwtMgr := testutil.NewJWTManager()
	h := api.NewAuthHandler(st, slog.Default(), jwtMgr, true)
	email := testutil.NewID() + "@test.com"
	userID := testutil.CreateTestUser(t, st, email, "correct-password", "user")

	_, err := h.RefreshToken(context.Background(), connect.NewRequest(&pm.RefreshTokenRequest{
		RefreshToken: "not-a-valid-token",
	}))
	require.Error(t, err)
	assert.Equal(t, 0, countUserEventsOfType(t, st, userID, "UserSessionRefreshed"),
		"a rejected refresh appends no event")
}

// --- CreateLuksToken → LuksTokenCreated ------------------------------------

func TestCreateLuksToken_AppendsAuditEvent(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceHandler(st, testutil.NewEncryptor(t), slog.Default(), api.NoOpSigner{})
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@user.com", "pass", "user")
	deviceID := testutil.CreateTestDevice(t, st, "luks-audit-device")
	actionID := testutil.CreateTestAction(t, st, userID, "Encrypt Disk", int(pm.ActionType_ACTION_TYPE_ENCRYPTION))
	testutil.AssignDeviceToUser(t, st, userID, deviceID, userID)
	ctx := testutil.UserContext(userID)

	_, err := h.CreateLuksToken(ctx, connect.NewRequest(&pm.CreateLuksTokenRequest{
		DeviceId: deviceID, ActionId: actionID,
	}))
	require.NoError(t, err)
	assert.Equal(t, 1, countDeviceEventsOfType(t, st, deviceID, "LuksTokenCreated"),
		"a successful token issue appends one LuksTokenCreated (no token material in payload)")
}

func TestCreateLuksToken_RejectedAppendsNoEvent(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceHandler(st, testutil.NewEncryptor(t), slog.Default(), api.NoOpSigner{})
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@user.com", "pass", "user")
	deviceID := testutil.CreateTestDevice(t, st, "luks-audit-reject")
	// No assignment → the user is out of scope, so the handler rejects.
	ctx := testutil.UserContext(userID)

	_, err := h.CreateLuksToken(ctx, connect.NewRequest(&pm.CreateLuksTokenRequest{
		DeviceId: deviceID, ActionId: testutil.NewID(),
	}))
	require.Error(t, err)
	assert.Equal(t, 0, countDeviceEventsOfType(t, st, deviceID, "LuksTokenCreated"),
		"a rejected token issue appends no event")
}
