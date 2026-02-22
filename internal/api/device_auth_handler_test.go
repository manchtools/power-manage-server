package api_test

import (
	"context"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

func newDeviceAuthHandler(t *testing.T, st *store.Store) *api.DeviceAuthHandler {
	t.Helper()
	jwtMgr := testutil.NewJWTManager()
	enc := testutil.NewEncryptor(t)
	return api.NewDeviceAuthHandler(st, jwtMgr, enc, "", "https://localhost:5173")
}

// --- AuthenticateDeviceUser ---

func TestAuthenticateDeviceUser_Success(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := newDeviceAuthHandler(t, st)

	email := testutil.NewID() + "@test.com"
	userID := testutil.CreateTestUser(t, st, email, "pass", "user")
	deviceID := testutil.CreateTestDevice(t, st, "test-host")
	testutil.AssignDeviceToUser(t, st, userID, deviceID, userID)

	resp, err := h.AuthenticateDeviceUser(context.Background(), connect.NewRequest(&pm.AuthenticateDeviceUserRequest{
		DeviceId: deviceID,
		Username: email,
		Password: "pass",
	}))
	require.NoError(t, err)
	assert.True(t, resp.Msg.Success)
	assert.NotEmpty(t, resp.Msg.SessionToken)
	assert.Equal(t, int64(28800), resp.Msg.SessionTtlSeconds)

	// Check user info
	require.NotNil(t, resp.Msg.User)
	assert.Equal(t, strings.SplitN(email, "@", 2)[0], resp.Msg.User.Username)
	assert.True(t, resp.Msg.User.Uid >= 60000 && resp.Msg.User.Uid < 65000)
	assert.Equal(t, resp.Msg.User.Uid, resp.Msg.User.Gid) // per-user GID
	assert.Equal(t, "/home/"+resp.Msg.User.Username, resp.Msg.User.HomeDir)
	assert.Equal(t, "/bin/bash", resp.Msg.User.Shell)
	assert.Contains(t, resp.Msg.User.Groups, "pm-users")
	assert.Equal(t, email, resp.Msg.User.Gecos)
}

func TestAuthenticateDeviceUser_WrongPassword(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := newDeviceAuthHandler(t, st)

	email := testutil.NewID() + "@test.com"
	userID := testutil.CreateTestUser(t, st, email, "pass", "user")
	deviceID := testutil.CreateTestDevice(t, st, "test-host")
	testutil.AssignDeviceToUser(t, st, userID, deviceID, userID)

	resp, err := h.AuthenticateDeviceUser(context.Background(), connect.NewRequest(&pm.AuthenticateDeviceUserRequest{
		DeviceId: deviceID,
		Username: email,
		Password: "wrong-password",
	}))
	require.NoError(t, err)
	assert.False(t, resp.Msg.Success)
	assert.Equal(t, "invalid credentials", resp.Msg.Error)
	assert.Empty(t, resp.Msg.SessionToken)
}

func TestAuthenticateDeviceUser_UserNotFound(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := newDeviceAuthHandler(t, st)

	deviceID := testutil.CreateTestDevice(t, st, "test-host")

	resp, err := h.AuthenticateDeviceUser(context.Background(), connect.NewRequest(&pm.AuthenticateDeviceUserRequest{
		DeviceId: deviceID,
		Username: "nonexistent@test.com",
		Password: "whatever",
	}))
	require.NoError(t, err)
	assert.False(t, resp.Msg.Success)
	assert.Equal(t, "invalid credentials", resp.Msg.Error)
}

func TestAuthenticateDeviceUser_DeviceNotFound(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := newDeviceAuthHandler(t, st)

	_, err := h.AuthenticateDeviceUser(context.Background(), connect.NewRequest(&pm.AuthenticateDeviceUserRequest{
		DeviceId: testutil.NewID(),
		Username: "user@test.com",
		Password: "pass",
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
}

func TestAuthenticateDeviceUser_NotAuthorizedForDevice(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := newDeviceAuthHandler(t, st)

	email := testutil.NewID() + "@test.com"
	userID := testutil.CreateTestUser(t, st, email, "pass", "user")
	otherUserID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "user")
	deviceID := testutil.CreateTestDevice(t, st, "test-host")
	// Assign device to a different user
	testutil.AssignDeviceToUser(t, st, otherUserID, deviceID, otherUserID)

	resp, err := h.AuthenticateDeviceUser(context.Background(), connect.NewRequest(&pm.AuthenticateDeviceUserRequest{
		DeviceId: deviceID,
		Username: email,
		Password: "pass",
	}))
	require.NoError(t, err)
	assert.False(t, resp.Msg.Success)
	assert.Equal(t, "user is not authorized for this device", resp.Msg.Error)
	_ = userID // used in setup
}

func TestAuthenticateDeviceUser_DisabledUser(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := newDeviceAuthHandler(t, st)

	email := testutil.NewID() + "@test.com"
	userID := testutil.CreateTestUser(t, st, email, "pass", "user")
	deviceID := testutil.CreateTestDevice(t, st, "test-host")
	testutil.AssignDeviceToUser(t, st, userID, deviceID, userID)

	// Disable the user
	err := st.AppendEvent(context.Background(), testutil.DisableEvent(userID))
	require.NoError(t, err)

	resp, err := h.AuthenticateDeviceUser(context.Background(), connect.NewRequest(&pm.AuthenticateDeviceUserRequest{
		DeviceId: deviceID,
		Username: email,
		Password: "pass",
	}))
	require.NoError(t, err)
	assert.False(t, resp.Msg.Success)
	assert.Equal(t, "account is disabled", resp.Msg.Error)
}

func TestAuthenticateDeviceUser_EmptyPasswordProbe(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := newDeviceAuthHandler(t, st)

	email := testutil.NewID() + "@test.com"
	userID := testutil.CreateTestUser(t, st, email, "pass", "user")
	deviceID := testutil.CreateTestDevice(t, st, "test-host")
	testutil.AssignDeviceToUser(t, st, userID, deviceID, userID)

	resp, err := h.AuthenticateDeviceUser(context.Background(), connect.NewRequest(&pm.AuthenticateDeviceUserRequest{
		DeviceId: deviceID,
		Username: email,
		Password: "",
	}))
	require.NoError(t, err)
	assert.False(t, resp.Msg.Success)
	assert.True(t, resp.Msg.PasswordRequired)
	assert.False(t, resp.Msg.OidcRequired)
}

func TestAuthenticateDeviceUser_OIDCOnlyUser(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := newDeviceAuthHandler(t, st)

	email := testutil.NewID() + "@test.com"
	userID := testutil.NewID()
	err := st.AppendEvent(context.Background(), testutil.SSOOnlyUserEvent(userID, email))
	require.NoError(t, err)

	deviceID := testutil.CreateTestDevice(t, st, "test-host")
	testutil.AssignDeviceToUser(t, st, userID, deviceID, userID)

	// Empty password probe should indicate OIDC required
	resp, err := h.AuthenticateDeviceUser(context.Background(), connect.NewRequest(&pm.AuthenticateDeviceUserRequest{
		DeviceId: deviceID,
		Username: email,
		Password: "",
	}))
	require.NoError(t, err)
	assert.False(t, resp.Msg.Success)
	assert.True(t, resp.Msg.OidcRequired)
	assert.False(t, resp.Msg.PasswordRequired)

	// Password attempt should also indicate OIDC required
	resp, err = h.AuthenticateDeviceUser(context.Background(), connect.NewRequest(&pm.AuthenticateDeviceUserRequest{
		DeviceId: deviceID,
		Username: email,
		Password: "any-password",
	}))
	require.NoError(t, err)
	assert.False(t, resp.Msg.Success)
	assert.True(t, resp.Msg.OidcRequired)
}

func TestAuthenticateDeviceUser_TOTPRequired(t *testing.T) {
	st := testutil.SetupPostgres(t)
	enc := testutil.NewEncryptor(t)
	jwtMgr := testutil.NewJWTManager()
	h := api.NewDeviceAuthHandler(st, jwtMgr, enc, "", "https://localhost:5173")

	email := testutil.NewID() + "@test.com"
	userID := testutil.CreateTestUser(t, st, email, "pass", "user")
	testutil.SetupTOTP(t, st, enc, userID, email)

	deviceID := testutil.CreateTestDevice(t, st, "test-host")
	testutil.AssignDeviceToUser(t, st, userID, deviceID, userID)

	// Authenticate without TOTP code
	resp, err := h.AuthenticateDeviceUser(context.Background(), connect.NewRequest(&pm.AuthenticateDeviceUserRequest{
		DeviceId: deviceID,
		Username: email,
		Password: "pass",
	}))
	require.NoError(t, err)
	assert.False(t, resp.Msg.Success)
	assert.True(t, resp.Msg.TotpRequired)
	assert.Empty(t, resp.Msg.SessionToken)
}

func TestAuthenticateDeviceUser_TOTPInvalid(t *testing.T) {
	st := testutil.SetupPostgres(t)
	enc := testutil.NewEncryptor(t)
	jwtMgr := testutil.NewJWTManager()
	h := api.NewDeviceAuthHandler(st, jwtMgr, enc, "", "https://localhost:5173")

	email := testutil.NewID() + "@test.com"
	userID := testutil.CreateTestUser(t, st, email, "pass", "user")
	testutil.SetupTOTP(t, st, enc, userID, email)

	deviceID := testutil.CreateTestDevice(t, st, "test-host")
	testutil.AssignDeviceToUser(t, st, userID, deviceID, userID)

	// Authenticate with wrong TOTP code
	resp, err := h.AuthenticateDeviceUser(context.Background(), connect.NewRequest(&pm.AuthenticateDeviceUserRequest{
		DeviceId: deviceID,
		Username: email,
		Password: "pass",
		TotpCode: "000000",
	}))
	require.NoError(t, err)
	assert.False(t, resp.Msg.Success)
	assert.Equal(t, "invalid TOTP code", resp.Msg.Error)
}

func TestAuthenticateDeviceUser_FirstLoginAutoAssigns(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := newDeviceAuthHandler(t, st)

	email := testutil.NewID() + "@test.com"
	testutil.CreateTestUser(t, st, email, "pass", "user")
	deviceID := testutil.CreateTestDevice(t, st, "test-host")
	// No assignment — device has no owner

	resp, err := h.AuthenticateDeviceUser(context.Background(), connect.NewRequest(&pm.AuthenticateDeviceUserRequest{
		DeviceId: deviceID,
		Username: email,
		Password: "pass",
	}))
	require.NoError(t, err)
	assert.True(t, resp.Msg.Success)
	assert.NotEmpty(t, resp.Msg.SessionToken)

	// Second user should be rejected now that the device has an owner
	email2 := testutil.NewID() + "@test.com"
	testutil.CreateTestUser(t, st, email2, "pass", "user")

	resp, err = h.AuthenticateDeviceUser(context.Background(), connect.NewRequest(&pm.AuthenticateDeviceUserRequest{
		DeviceId: deviceID,
		Username: email2,
		Password: "pass",
	}))
	require.NoError(t, err)
	assert.False(t, resp.Msg.Success)
	assert.Equal(t, "user is not authorized for this device", resp.Msg.Error)
}

func TestAuthenticateDeviceUser_PasswordDisabledByIdP(t *testing.T) {
	st := testutil.SetupPostgres(t)
	enc := testutil.NewEncryptor(t)
	jwtMgr := testutil.NewJWTManager()
	h := api.NewDeviceAuthHandler(st, jwtMgr, enc, "", "https://localhost:5173")

	email := testutil.NewID() + "@test.com"
	userID := testutil.CreateTestUser(t, st, email, "pass", "user")
	deviceID := testutil.CreateTestDevice(t, st, "test-host")
	testutil.AssignDeviceToUser(t, st, userID, deviceID, userID)

	// Create a provider with disable_password_for_linked=true
	providerID := testutil.NewID()
	err := st.AppendEvent(context.Background(), store.Event{
		StreamType: "identity_provider",
		StreamID:   providerID,
		EventType:  "IdentityProviderCreated",
		Data: map[string]any{
			"name":                        "Corporate SSO",
			"slug":                        "corporate",
			"provider_type":               "oidc",
			"client_id":                   "client-corp",
			"client_secret_encrypted":     "encrypted",
			"issuer_url":                  "https://corp.example.com",
			"enabled":                     true,
			"disable_password_for_linked": true,
		},
		ActorType: "system",
		ActorID:   "test",
	})
	require.NoError(t, err)

	// Link user to this provider
	testutil.CreateTestIdentityLink(t, st, userID, providerID, "ext-123", email)

	// Password auth should be blocked, OIDC required
	resp, err := h.AuthenticateDeviceUser(context.Background(), connect.NewRequest(&pm.AuthenticateDeviceUserRequest{
		DeviceId: deviceID,
		Username: email,
		Password: "pass",
	}))
	require.NoError(t, err)
	assert.False(t, resp.Msg.Success)
	assert.True(t, resp.Msg.OidcRequired)
}

func TestAuthenticateDeviceUser_UIDDeterministic(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := newDeviceAuthHandler(t, st)

	email := testutil.NewID() + "@test.com"
	testutil.CreateTestUser(t, st, email, "pass", "user")
	deviceID := testutil.CreateTestDevice(t, st, "test-host")
	// No owner — first login auto-assigns

	// First auth
	resp1, err := h.AuthenticateDeviceUser(context.Background(), connect.NewRequest(&pm.AuthenticateDeviceUserRequest{
		DeviceId: deviceID,
		Username: email,
		Password: "pass",
	}))
	require.NoError(t, err)
	assert.True(t, resp1.Msg.Success)

	// Second auth — same user, same device
	resp2, err := h.AuthenticateDeviceUser(context.Background(), connect.NewRequest(&pm.AuthenticateDeviceUserRequest{
		DeviceId: deviceID,
		Username: email,
		Password: "pass",
	}))
	require.NoError(t, err)
	assert.True(t, resp2.Msg.Success)

	// UIDs should be identical
	assert.Equal(t, resp1.Msg.User.Uid, resp2.Msg.User.Uid)
	assert.Equal(t, resp1.Msg.User.Gid, resp2.Msg.User.Gid)
}

// --- ListDeviceUsers ---

func TestListDeviceUsers_ReturnsAssignedOwner(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := newDeviceAuthHandler(t, st)

	email := testutil.NewID() + "@test.com"
	userID := testutil.CreateTestUser(t, st, email, "pass", "user")
	deviceID := testutil.CreateTestDevice(t, st, "test-host")
	testutil.AssignDeviceToUser(t, st, userID, deviceID, userID)

	resp, err := h.ListDeviceUsers(context.Background(), connect.NewRequest(&pm.ListDeviceUsersRequest{
		DeviceId: deviceID,
	}))
	require.NoError(t, err)
	require.Len(t, resp.Msg.Users, 1)
	assert.Equal(t, strings.SplitN(email, "@", 2)[0], resp.Msg.Users[0].Username)
	assert.Equal(t, email, resp.Msg.Users[0].Gecos)
}

func TestListDeviceUsers_Empty(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := newDeviceAuthHandler(t, st)

	deviceID := testutil.CreateTestDevice(t, st, "test-host")

	resp, err := h.ListDeviceUsers(context.Background(), connect.NewRequest(&pm.ListDeviceUsersRequest{
		DeviceId: deviceID,
	}))
	require.NoError(t, err)
	assert.Empty(t, resp.Msg.Users)
}

func TestListDeviceUsers_DeviceNotFound(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := newDeviceAuthHandler(t, st)

	_, err := h.ListDeviceUsers(context.Background(), connect.NewRequest(&pm.ListDeviceUsersRequest{
		DeviceId: testutil.NewID(),
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
}

func TestListDeviceUsers_ExcludesDisabledOwner(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := newDeviceAuthHandler(t, st)

	email := testutil.NewID() + "@test.com"
	userID := testutil.CreateTestUser(t, st, email, "pass", "user")
	deviceID := testutil.CreateTestDevice(t, st, "test-host")
	testutil.AssignDeviceToUser(t, st, userID, deviceID, userID)

	// Disable the user
	err := st.AppendEvent(context.Background(), testutil.DisableEvent(userID))
	require.NoError(t, err)

	resp, err := h.ListDeviceUsers(context.Background(), connect.NewRequest(&pm.ListDeviceUsersRequest{
		DeviceId: deviceID,
	}))
	require.NoError(t, err)
	assert.Empty(t, resp.Msg.Users)
}

// --- GetDeviceLoginURL ---

func TestGetDeviceLoginURL_ReturnsURL(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := newDeviceAuthHandler(t, st)

	deviceID := testutil.CreateTestDevice(t, st, "test-host")

	resp, err := h.GetDeviceLoginURL(context.Background(), connect.NewRequest(&pm.GetDeviceLoginURLRequest{
		DeviceId:     deviceID,
		CallbackPort: 12345,
		Username:     "user@test.com",
	}))
	require.NoError(t, err)
	assert.Contains(t, resp.Msg.LoginUrl, "device_id="+deviceID)
	assert.Contains(t, resp.Msg.LoginUrl, "callback_port=12345")
	assert.Contains(t, resp.Msg.LoginUrl, "state=")
	assert.Contains(t, resp.Msg.LoginUrl, "username=user@test.com")
}

func TestGetDeviceLoginURL_DefaultsToBuiltInURL(t *testing.T) {
	st := testutil.SetupPostgres(t)
	jwtMgr := testutil.NewJWTManager()
	enc := testutil.NewEncryptor(t)
	// Empty deviceLoginURL, externalURL = "https://pm.example.com"
	h := api.NewDeviceAuthHandler(st, jwtMgr, enc, "", "https://pm.example.com")

	deviceID := testutil.CreateTestDevice(t, st, "test-host")

	resp, err := h.GetDeviceLoginURL(context.Background(), connect.NewRequest(&pm.GetDeviceLoginURLRequest{
		DeviceId:     deviceID,
		CallbackPort: 8080,
	}))
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(resp.Msg.LoginUrl, "https://pm.example.com/app/device-login?"))
}

func TestGetDeviceLoginURL_UsesConfiguredBaseURL(t *testing.T) {
	st := testutil.SetupPostgres(t)
	jwtMgr := testutil.NewJWTManager()
	enc := testutil.NewEncryptor(t)
	h := api.NewDeviceAuthHandler(st, jwtMgr, enc, "https://custom-ui.example.com/login", "https://pm.example.com")

	deviceID := testutil.CreateTestDevice(t, st, "test-host")

	resp, err := h.GetDeviceLoginURL(context.Background(), connect.NewRequest(&pm.GetDeviceLoginURLRequest{
		DeviceId:     deviceID,
		CallbackPort: 8080,
	}))
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(resp.Msg.LoginUrl, "https://custom-ui.example.com/login?"))
}

func TestGetDeviceLoginURL_DeviceNotFound(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := newDeviceAuthHandler(t, st)

	_, err := h.GetDeviceLoginURL(context.Background(), connect.NewRequest(&pm.GetDeviceLoginURLRequest{
		DeviceId:     testutil.NewID(),
		CallbackPort: 8080,
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
}

// --- DeviceLoginCallback ---

func TestDeviceLoginCallback_Unimplemented(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := newDeviceAuthHandler(t, st)

	_, err := h.DeviceLoginCallback(context.Background(), connect.NewRequest(&pm.DeviceLoginCallbackRequest{
		CallbackToken: "some-token",
		DeviceId:      testutil.NewID(),
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeUnimplemented, connect.CodeOf(err))
}
