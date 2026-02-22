package api_test

import (
	"context"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

func TestSetupTOTP(t *testing.T) {
	st := testutil.SetupPostgres(t)
	jwtMgr := testutil.NewJWTManager()
	enc := testutil.NewEncryptor(t)
	h := api.NewTOTPHandler(st, jwtMgr, enc, "TestApp")

	email := testutil.NewID() + "@test.com"
	userID := testutil.CreateTestUser(t, st, email, "password", "user")
	ctx := auth.WithUser(context.Background(), &auth.UserContext{ID: userID, Email: email, Permissions: auth.DefaultUserPermissions()})

	resp, err := h.SetupTOTP(ctx, connect.NewRequest(&pm.SetupTOTPRequest{}))
	require.NoError(t, err)

	assert.NotEmpty(t, resp.Msg.Secret)
	assert.Contains(t, resp.Msg.QrUri, "otpauth://totp/")
	assert.Len(t, resp.Msg.BackupCodes, 10)

	// Verify all backup codes are unique
	seen := make(map[string]bool)
	for _, code := range resp.Msg.BackupCodes {
		assert.False(t, seen[code])
		seen[code] = true
	}
}

func TestVerifyTOTP_Success(t *testing.T) {
	st := testutil.SetupPostgres(t)
	jwtMgr := testutil.NewJWTManager()
	enc := testutil.NewEncryptor(t)
	h := api.NewTOTPHandler(st, jwtMgr, enc, "TestApp")

	email := testutil.NewID() + "@test.com"
	userID := testutil.CreateTestUser(t, st, email, "password", "user")
	ctx := auth.WithUser(context.Background(), &auth.UserContext{ID: userID, Email: email, Permissions: auth.DefaultUserPermissions()})

	// Setup TOTP
	setupResp, err := h.SetupTOTP(ctx, connect.NewRequest(&pm.SetupTOTPRequest{}))
	require.NoError(t, err)

	// Generate valid code
	code, err := totp.GenerateCode(setupResp.Msg.Secret, time.Now())
	require.NoError(t, err)

	// Verify
	verifyResp, err := h.VerifyTOTP(ctx, connect.NewRequest(&pm.VerifyTOTPRequest{Code: code}))
	require.NoError(t, err)
	assert.True(t, verifyResp.Msg.Success)

	// Check TOTP is now enabled
	statusResp, err := h.GetTOTPStatus(ctx, connect.NewRequest(&pm.GetTOTPStatusRequest{}))
	require.NoError(t, err)
	assert.True(t, statusResp.Msg.Enabled)
	assert.Equal(t, int32(10), statusResp.Msg.BackupCodesRemaining)
}

func TestVerifyTOTP_InvalidCode(t *testing.T) {
	st := testutil.SetupPostgres(t)
	jwtMgr := testutil.NewJWTManager()
	enc := testutil.NewEncryptor(t)
	h := api.NewTOTPHandler(st, jwtMgr, enc, "TestApp")

	email := testutil.NewID() + "@test.com"
	userID := testutil.CreateTestUser(t, st, email, "password", "user")
	ctx := auth.WithUser(context.Background(), &auth.UserContext{ID: userID, Email: email, Permissions: auth.DefaultUserPermissions()})

	// Setup TOTP
	_, err := h.SetupTOTP(ctx, connect.NewRequest(&pm.SetupTOTPRequest{}))
	require.NoError(t, err)

	// Verify with wrong code
	verifyResp, err := h.VerifyTOTP(ctx, connect.NewRequest(&pm.VerifyTOTPRequest{Code: "000000"}))
	require.NoError(t, err)
	assert.False(t, verifyResp.Msg.Success)
}

func TestVerifyTOTP_NoSetup(t *testing.T) {
	st := testutil.SetupPostgres(t)
	jwtMgr := testutil.NewJWTManager()
	enc := testutil.NewEncryptor(t)
	h := api.NewTOTPHandler(st, jwtMgr, enc, "TestApp")

	email := testutil.NewID() + "@test.com"
	userID := testutil.CreateTestUser(t, st, email, "password", "user")
	ctx := auth.WithUser(context.Background(), &auth.UserContext{ID: userID, Email: email, Permissions: auth.DefaultUserPermissions()})

	_, err := h.VerifyTOTP(ctx, connect.NewRequest(&pm.VerifyTOTPRequest{Code: "123456"}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err))
}

func TestDisableTOTP(t *testing.T) {
	st := testutil.SetupPostgres(t)
	jwtMgr := testutil.NewJWTManager()
	enc := testutil.NewEncryptor(t)
	h := api.NewTOTPHandler(st, jwtMgr, enc, "TestApp")

	email := testutil.NewID() + "@test.com"
	userID := testutil.CreateTestUser(t, st, email, "password", "user")
	ctx := auth.WithUser(context.Background(), &auth.UserContext{ID: userID, Email: email, Permissions: auth.DefaultUserPermissions()})

	// Setup and verify TOTP
	testutil.SetupTOTP(t, st, enc, userID, email)

	// Disable with correct password
	_, err := h.DisableTOTP(ctx, connect.NewRequest(&pm.DisableTOTPRequest{Password: "password"}))
	require.NoError(t, err)

	// TOTP should be disabled
	statusResp, err := h.GetTOTPStatus(ctx, connect.NewRequest(&pm.GetTOTPStatusRequest{}))
	require.NoError(t, err)
	assert.False(t, statusResp.Msg.Enabled)
}

func TestDisableTOTP_WrongPassword(t *testing.T) {
	st := testutil.SetupPostgres(t)
	jwtMgr := testutil.NewJWTManager()
	enc := testutil.NewEncryptor(t)
	h := api.NewTOTPHandler(st, jwtMgr, enc, "TestApp")

	email := testutil.NewID() + "@test.com"
	userID := testutil.CreateTestUser(t, st, email, "password", "user")
	ctx := auth.WithUser(context.Background(), &auth.UserContext{ID: userID, Email: email, Permissions: auth.DefaultUserPermissions()})

	testutil.SetupTOTP(t, st, enc, userID, email)

	_, err := h.DisableTOTP(ctx, connect.NewRequest(&pm.DisableTOTPRequest{Password: "wrong-password"}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
}

func TestDisableTOTP_NotEnabled(t *testing.T) {
	st := testutil.SetupPostgres(t)
	jwtMgr := testutil.NewJWTManager()
	enc := testutil.NewEncryptor(t)
	h := api.NewTOTPHandler(st, jwtMgr, enc, "TestApp")

	email := testutil.NewID() + "@test.com"
	userID := testutil.CreateTestUser(t, st, email, "password", "user")
	ctx := auth.WithUser(context.Background(), &auth.UserContext{ID: userID, Email: email, Permissions: auth.DefaultUserPermissions()})

	_, err := h.DisableTOTP(ctx, connect.NewRequest(&pm.DisableTOTPRequest{Password: "password"}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err))
}

func TestGetTOTPStatus_NotSetup(t *testing.T) {
	st := testutil.SetupPostgres(t)
	jwtMgr := testutil.NewJWTManager()
	enc := testutil.NewEncryptor(t)
	h := api.NewTOTPHandler(st, jwtMgr, enc, "TestApp")

	email := testutil.NewID() + "@test.com"
	userID := testutil.CreateTestUser(t, st, email, "password", "user")
	ctx := auth.WithUser(context.Background(), &auth.UserContext{ID: userID, Email: email, Permissions: auth.DefaultUserPermissions()})

	resp, err := h.GetTOTPStatus(ctx, connect.NewRequest(&pm.GetTOTPStatusRequest{}))
	require.NoError(t, err)
	assert.False(t, resp.Msg.Enabled)
	assert.Equal(t, int32(0), resp.Msg.BackupCodesRemaining)
}

func TestRegenerateBackupCodes(t *testing.T) {
	st := testutil.SetupPostgres(t)
	jwtMgr := testutil.NewJWTManager()
	enc := testutil.NewEncryptor(t)
	h := api.NewTOTPHandler(st, jwtMgr, enc, "TestApp")

	email := testutil.NewID() + "@test.com"
	userID := testutil.CreateTestUser(t, st, email, "password", "user")
	ctx := auth.WithUser(context.Background(), &auth.UserContext{ID: userID, Email: email, Permissions: auth.DefaultUserPermissions()})

	testutil.SetupTOTP(t, st, enc, userID, email)

	resp, err := h.RegenerateBackupCodes(ctx, connect.NewRequest(&pm.RegenerateBackupCodesRequest{Password: "password"}))
	require.NoError(t, err)
	assert.Len(t, resp.Msg.BackupCodes, 10)

	// Should still show 10 backup codes remaining
	statusResp, err := h.GetTOTPStatus(ctx, connect.NewRequest(&pm.GetTOTPStatusRequest{}))
	require.NoError(t, err)
	assert.Equal(t, int32(10), statusResp.Msg.BackupCodesRemaining)
}

func TestRegenerateBackupCodes_WrongPassword(t *testing.T) {
	st := testutil.SetupPostgres(t)
	jwtMgr := testutil.NewJWTManager()
	enc := testutil.NewEncryptor(t)
	h := api.NewTOTPHandler(st, jwtMgr, enc, "TestApp")

	email := testutil.NewID() + "@test.com"
	userID := testutil.CreateTestUser(t, st, email, "password", "user")
	ctx := auth.WithUser(context.Background(), &auth.UserContext{ID: userID, Email: email, Permissions: auth.DefaultUserPermissions()})

	testutil.SetupTOTP(t, st, enc, userID, email)

	_, err := h.RegenerateBackupCodes(ctx, connect.NewRequest(&pm.RegenerateBackupCodesRequest{Password: "wrong-password"}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
}

func TestVerifyLoginTOTP_Success(t *testing.T) {
	st := testutil.SetupPostgres(t)
	jwtMgr := testutil.NewJWTManager()
	enc := testutil.NewEncryptor(t)
	h := api.NewTOTPHandler(st, jwtMgr, enc, "TestApp")

	email := testutil.NewID() + "@test.com"
	userID := testutil.CreateTestUser(t, st, email, "password", "user")

	secret := testutil.SetupTOTP(t, st, enc, userID, email)

	// Generate challenge token
	challenge, err := jwtMgr.GenerateTOTPChallenge(userID, email, 0)
	require.NoError(t, err)

	// Generate valid TOTP code
	code, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)

	resp, err := h.VerifyLoginTOTP(context.Background(), connect.NewRequest(&pm.VerifyLoginTOTPRequest{
		Challenge: challenge,
		Code:      code,
	}))
	require.NoError(t, err)

	assert.NotEmpty(t, resp.Msg.AccessToken)
	assert.NotEmpty(t, resp.Msg.RefreshToken)
	assert.NotNil(t, resp.Msg.ExpiresAt)
	assert.NotNil(t, resp.Msg.User)
	assert.Equal(t, email, resp.Msg.User.Email)
}

func TestVerifyLoginTOTP_InvalidCode(t *testing.T) {
	st := testutil.SetupPostgres(t)
	jwtMgr := testutil.NewJWTManager()
	enc := testutil.NewEncryptor(t)
	h := api.NewTOTPHandler(st, jwtMgr, enc, "TestApp")

	email := testutil.NewID() + "@test.com"
	userID := testutil.CreateTestUser(t, st, email, "password", "user")

	testutil.SetupTOTP(t, st, enc, userID, email)

	challenge, err := jwtMgr.GenerateTOTPChallenge(userID, email, 0)
	require.NoError(t, err)

	_, err = h.VerifyLoginTOTP(context.Background(), connect.NewRequest(&pm.VerifyLoginTOTPRequest{
		Challenge: challenge,
		Code:      "000000",
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
}

func TestVerifyLoginTOTP_InvalidChallenge(t *testing.T) {
	st := testutil.SetupPostgres(t)
	jwtMgr := testutil.NewJWTManager()
	enc := testutil.NewEncryptor(t)
	h := api.NewTOTPHandler(st, jwtMgr, enc, "TestApp")

	_, err := h.VerifyLoginTOTP(context.Background(), connect.NewRequest(&pm.VerifyLoginTOTPRequest{
		Challenge: "invalid-token",
		Code:      "123456",
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
}

func TestVerifyLoginTOTP_BackupCode(t *testing.T) {
	st := testutil.SetupPostgres(t)
	jwtMgr := testutil.NewJWTManager()
	enc := testutil.NewEncryptor(t)
	h := api.NewTOTPHandler(st, jwtMgr, enc, "TestApp")

	email := testutil.NewID() + "@test.com"
	userID := testutil.CreateTestUser(t, st, email, "password", "user")
	ctx := auth.WithUser(context.Background(), &auth.UserContext{ID: userID, Email: email, Permissions: auth.DefaultUserPermissions()})

	// Setup TOTP via handler to get backup codes
	setupResp, err := h.SetupTOTP(ctx, connect.NewRequest(&pm.SetupTOTPRequest{}))
	require.NoError(t, err)

	// Verify TOTP to enable it
	code, err := totp.GenerateCode(setupResp.Msg.Secret, time.Now())
	require.NoError(t, err)
	_, err = h.VerifyTOTP(ctx, connect.NewRequest(&pm.VerifyTOTPRequest{Code: code}))
	require.NoError(t, err)

	// Generate challenge
	challenge, err := jwtMgr.GenerateTOTPChallenge(userID, email, 0)
	require.NoError(t, err)

	// Use a backup code
	resp, err := h.VerifyLoginTOTP(context.Background(), connect.NewRequest(&pm.VerifyLoginTOTPRequest{
		Challenge: challenge,
		Code:      setupResp.Msg.BackupCodes[0],
	}))
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Msg.AccessToken)

	// Backup codes remaining should decrease
	statusResp, err := h.GetTOTPStatus(ctx, connect.NewRequest(&pm.GetTOTPStatusRequest{}))
	require.NoError(t, err)
	assert.Equal(t, int32(9), statusResp.Msg.BackupCodesRemaining)
}
