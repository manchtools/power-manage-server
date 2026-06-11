package api_test

import (
	"context"
	"log/slog"
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
	h := api.NewTOTPHandler(st, slog.Default(), jwtMgr, enc, "TestApp")

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
	h := api.NewTOTPHandler(st, slog.Default(), jwtMgr, enc, "TestApp")

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
	h := api.NewTOTPHandler(st, slog.Default(), jwtMgr, enc, "TestApp")

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
	h := api.NewTOTPHandler(st, slog.Default(), jwtMgr, enc, "TestApp")

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
	h := api.NewTOTPHandler(st, slog.Default(), jwtMgr, enc, "TestApp")

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
	h := api.NewTOTPHandler(st, slog.Default(), jwtMgr, enc, "TestApp")

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
	h := api.NewTOTPHandler(st, slog.Default(), jwtMgr, enc, "TestApp")

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
	h := api.NewTOTPHandler(st, slog.Default(), jwtMgr, enc, "TestApp")

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
	h := api.NewTOTPHandler(st, slog.Default(), jwtMgr, enc, "TestApp")

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
	h := api.NewTOTPHandler(st, slog.Default(), jwtMgr, enc, "TestApp")

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
	h := api.NewTOTPHandler(st, slog.Default(), jwtMgr, enc, "TestApp")

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

// TestVerifyLoginTOTP_ChallengeIsSingleUse pins that a TOTP login challenge is
// usable exactly once: after a successful verification the same challenge JWT
// (still well within its 5-min TTL) is rejected, even with a fresh valid code.
// Without this the challenge is replayable for its whole life.
func TestVerifyLoginTOTP_ChallengeIsSingleUse(t *testing.T) {
	st := testutil.SetupPostgres(t)
	jwtMgr := testutil.NewJWTManager()
	enc := testutil.NewEncryptor(t)
	h := api.NewTOTPHandler(st, slog.Default(), jwtMgr, enc, "TestApp")

	email := testutil.NewID() + "@test.com"
	userID := testutil.CreateTestUser(t, st, email, "password", "user")
	secret := testutil.SetupTOTP(t, st, enc, userID, email)

	challenge, err := jwtMgr.GenerateTOTPChallenge(userID, email, 0)
	require.NoError(t, err)

	code, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)

	// First use succeeds.
	_, err = h.VerifyLoginTOTP(context.Background(), connect.NewRequest(&pm.VerifyLoginTOTPRequest{
		Challenge: challenge,
		Code:      code,
	}))
	require.NoError(t, err)

	// Reusing the SAME challenge is rejected, even with a fresh valid code.
	freshCode, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)
	_, err = h.VerifyLoginTOTP(context.Background(), connect.NewRequest(&pm.VerifyLoginTOTPRequest{
		Challenge: challenge,
		Code:      freshCode,
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err))
	assert.Contains(t, err.Error(), "already used")
}

// TestVerifyLoginTOTP_WrongCodeStillConsumesChallenge pins consume-on-
// presentation: even a FAILED first attempt burns the challenge, so an attacker
// cannot brute-force multiple codes against one challenge. The wrong guess
// burns it; a subsequent correct code on the same challenge is rejected, NOT
// accepted.
func TestVerifyLoginTOTP_WrongCodeStillConsumesChallenge(t *testing.T) {
	st := testutil.SetupPostgres(t)
	jwtMgr := testutil.NewJWTManager()
	enc := testutil.NewEncryptor(t)
	h := api.NewTOTPHandler(st, slog.Default(), jwtMgr, enc, "TestApp")

	email := testutil.NewID() + "@test.com"
	userID := testutil.CreateTestUser(t, st, email, "password", "user")
	secret := testutil.SetupTOTP(t, st, enc, userID, email)

	challenge, err := jwtMgr.GenerateTOTPChallenge(userID, email, 0)
	require.NoError(t, err)

	// First attempt with a wrong code fails (and consumes the challenge).
	_, err = h.VerifyLoginTOTP(context.Background(), connect.NewRequest(&pm.VerifyLoginTOTPRequest{
		Challenge: challenge,
		Code:      "000000",
	}))
	require.Error(t, err)

	// A correct code on the SAME challenge must now be rejected as already used,
	// not accepted — proving the wrong guess burned the one allowed attempt.
	code, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)
	resp, err := h.VerifyLoginTOTP(context.Background(), connect.NewRequest(&pm.VerifyLoginTOTPRequest{
		Challenge: challenge,
		Code:      code,
	}))
	require.Error(t, err)
	assert.Nil(t, resp)
	assert.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err))
	assert.Contains(t, err.Error(), "already used")
}

// TestVerifyLoginTOTP_PerAccountFailedAttemptLimit pins the per-account 2FA
// brute-force ceiling (#381): after totpAccountFailLimit (10) failed
// VerifyLoginTOTP attempts the account is throttled, independent of source IP
// and even with a fresh valid challenge. Uses a no-backup-code TOTP user so the
// 11 failed attempts don't each run the bcrypt backup-code loop.
func TestVerifyLoginTOTP_PerAccountFailedAttemptLimit(t *testing.T) {
	st := testutil.SetupPostgres(t)
	jwtMgr := testutil.NewJWTManager()
	enc := testutil.NewEncryptor(t)
	h := api.NewTOTPHandler(st, slog.Default(), jwtMgr, enc, "TestApp")

	email := testutil.NewID() + "@test.com"
	userID := testutil.CreateTestUser(t, st, email, "password", "user")
	testutil.SetupTOTPCheapBackup(t, st, enc, userID, email)

	for i := 0; i < 10; i++ {
		challenge, err := jwtMgr.GenerateTOTPChallenge(userID, email, 0)
		require.NoError(t, err)
		_, err = h.VerifyLoginTOTP(context.Background(), connect.NewRequest(&pm.VerifyLoginTOTPRequest{
			Challenge: challenge,
			Code:      "000000",
		}))
		require.Error(t, err)
		assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err), "attempt %d should be invalid TOTP, not yet throttled", i+1)
	}

	// 11th: a fresh, valid challenge — but the account is now throttled.
	challenge, err := jwtMgr.GenerateTOTPChallenge(userID, email, 0)
	require.NoError(t, err)
	_, err = h.VerifyLoginTOTP(context.Background(), connect.NewRequest(&pm.VerifyLoginTOTPRequest{
		Challenge: challenge,
		Code:      "000000",
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeResourceExhausted, connect.CodeOf(err), "account should be throttled after 10 failed TOTP attempts")
}

func TestVerifyLoginTOTP_InvalidCode(t *testing.T) {
	st := testutil.SetupPostgres(t)
	jwtMgr := testutil.NewJWTManager()
	enc := testutil.NewEncryptor(t)
	h := api.NewTOTPHandler(st, slog.Default(), jwtMgr, enc, "TestApp")

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
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}

func TestVerifyLoginTOTP_InvalidChallenge(t *testing.T) {
	st := testutil.SetupPostgres(t)
	jwtMgr := testutil.NewJWTManager()
	enc := testutil.NewEncryptor(t)
	h := api.NewTOTPHandler(st, slog.Default(), jwtMgr, enc, "TestApp")

	_, err := h.VerifyLoginTOTP(context.Background(), connect.NewRequest(&pm.VerifyLoginTOTPRequest{
		Challenge: "invalid-token",
		Code:      "123456",
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err))
}

func TestVerifyLoginTOTP_BackupCode(t *testing.T) {
	st := testutil.SetupPostgres(t)
	jwtMgr := testutil.NewJWTManager()
	enc := testutil.NewEncryptor(t)
	h := api.NewTOTPHandler(st, slog.Default(), jwtMgr, enc, "TestApp")

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

// TestVerifyLoginTOTP_BackupCodeRaceCondition exercises the audit
// F-07 follow-up: when two requests submit the same backup code
// concurrently, exactly one must succeed and the other must fail
// with "invalid TOTP code". Pre-fix, both passed the in-memory
// VerifyBackupCode check and both got auth-success tokens, even
// though only one TOTPBackupCodeUsed event landed and only one
// projection-update fired. The post-fix path uses
// AppendEventWithVersion so the second concurrent attempt fails the
// UNIQUE(stream_type, stream_id, stream_version) constraint and the
// handler maps the resulting ErrVersionConflict to InvalidArgument.
func TestVerifyLoginTOTP_BackupCodeRaceCondition(t *testing.T) {
	st := testutil.SetupPostgres(t)
	jwtMgr := testutil.NewJWTManager()
	enc := testutil.NewEncryptor(t)
	h := api.NewTOTPHandler(st, slog.Default(), jwtMgr, enc, "TestApp")

	email := testutil.NewID() + "@test.com"
	userID := testutil.CreateTestUser(t, st, email, "password", "user")
	ctx := auth.WithUser(context.Background(), &auth.UserContext{ID: userID, Email: email, Permissions: auth.DefaultUserPermissions()})

	setupResp, err := h.SetupTOTP(ctx, connect.NewRequest(&pm.SetupTOTPRequest{}))
	require.NoError(t, err)
	code, err := totp.GenerateCode(setupResp.Msg.Secret, time.Now())
	require.NoError(t, err)
	_, err = h.VerifyTOTP(ctx, connect.NewRequest(&pm.VerifyTOTPRequest{Code: code}))
	require.NoError(t, err)

	// Two independent challenges for the same user — both legitimate
	// from a JWT perspective; the race is at the event-store level.
	challengeA, err := jwtMgr.GenerateTOTPChallenge(userID, email, 0)
	require.NoError(t, err)
	challengeB, err := jwtMgr.GenerateTOTPChallenge(userID, email, 0)
	require.NoError(t, err)

	backup := setupResp.Msg.BackupCodes[0]

	// Fire both calls concurrently and wait for both results.
	type result struct {
		ok  bool
		err error
	}
	results := make(chan result, 2)
	doVerify := func(challenge string) {
		_, err := h.VerifyLoginTOTP(context.Background(), connect.NewRequest(&pm.VerifyLoginTOTPRequest{
			Challenge: challenge,
			Code:      backup,
		}))
		results <- result{ok: err == nil, err: err}
	}
	go doVerify(challengeA)
	go doVerify(challengeB)
	r1 := <-results
	r2 := <-results

	// Exactly one must succeed.
	successes := 0
	if r1.ok {
		successes++
	}
	if r2.ok {
		successes++
	}
	assert.Equal(t, 1, successes,
		"backup-code race must allow exactly one consumer; got %d (results: %+v %+v)",
		successes, r1, r2)

	// The loser must surface as invalid TOTP, NOT internal error.
	if !r1.ok {
		assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(r1.err),
			"race loser must return CodeInvalidArgument so the client retries with a fresh code")
	}
	if !r2.ok {
		assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(r2.err),
			"race loser must return CodeInvalidArgument so the client retries with a fresh code")
	}

	// Backup-codes-remaining decreased by exactly one (the winner),
	// not two — proves the projection wasn't double-decremented.
	statusResp, err := h.GetTOTPStatus(ctx, connect.NewRequest(&pm.GetTOTPStatusRequest{}))
	require.NoError(t, err)
	assert.Equal(t, int32(9), statusResp.Msg.BackupCodesRemaining,
		"exactly one code consumed despite two concurrent attempts")
}
