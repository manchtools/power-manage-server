package api

import (
	"context"
	"errors"
	"log/slog"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/types/known/timestamppb"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/auth/totp"
	"github.com/manchtools/power-manage/server/internal/crypto"
	"github.com/manchtools/power-manage/server/internal/middleware"
	"github.com/manchtools/power-manage/server/internal/store"
)

// TOTPHandler handles TOTP two-factor authentication RPCs.
type TOTPHandler struct {
	store      *store.Store
	logger     *slog.Logger
	jwtManager *auth.JWTManager
	encryptor  *crypto.Encryptor
	issuer     string
}

// NewTOTPHandler creates a new TOTP handler.
func NewTOTPHandler(st *store.Store, logger *slog.Logger, jwtManager *auth.JWTManager, enc *crypto.Encryptor, issuer string) *TOTPHandler {
	if issuer == "" {
		issuer = totp.DefaultIssuer
	}
	return &TOTPHandler{
		store:      st,
		logger:     logger,
		jwtManager: jwtManager,
		encryptor:  enc,
		issuer:     issuer,
	}
}

// SetupTOTP generates a new TOTP secret and backup codes for the current user.
func (h *TOTPHandler) SetupTOTP(ctx context.Context, req *connect.Request[pm.SetupTOTPRequest]) (*connect.Response[pm.SetupTOTPResponse], error) {
	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	// SSO-only users cannot set up TOTP — they must use their identity provider's MFA
	user, err := h.store.Queries().GetUserByID(ctx, userCtx.ID)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get user")
	}
	if !user.HasPassword {
		return nil, apiErrorCtx(ctx, ErrTOTPSSONotAllowed, connect.CodeFailedPrecondition, "TOTP cannot be configured for accounts using federated login (SSO); use your identity provider's MFA instead")
	}

	// Generate TOTP key
	key, err := totp.GenerateKey(h.issuer, userCtx.Email)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to generate TOTP key")
	}

	// Generate backup codes
	codes, hashes, err := totp.GenerateBackupCodes()
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to generate backup codes")
	}

	// Encrypt the TOTP secret
	encryptedSecret, err := h.encryptor.Encrypt(key.Secret())
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to encrypt TOTP secret")
	}

	// Store via event
	hashesAny := make([]any, len(hashes))
	for i, h := range hashes {
		hashesAny[i] = h
	}

	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "totp",
		StreamID:   userCtx.ID,
		EventType:  "TOTPSetupInitiated",
		Data: map[string]any{
			"secret_encrypted":  encryptedSecret,
			"backup_codes_hash": hashes,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	}, "failed to save TOTP setup"); err != nil {
		return nil, err
	}

	return connect.NewResponse(&pm.SetupTOTPResponse{
		Secret:      key.Secret(),
		QrUri:       key.URL(),
		BackupCodes: codes,
	}), nil
}

// VerifyTOTP confirms TOTP setup by validating a code from the user's authenticator app.
func (h *TOTPHandler) VerifyTOTP(ctx context.Context, req *connect.Request[pm.VerifyTOTPRequest]) (*connect.Response[pm.VerifyTOTPResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	// Get pending TOTP setup
	totpRecord, err := h.store.Queries().GetTOTPByUserID(ctx, userCtx.ID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apiErrorCtx(ctx, ErrTOTPNotSetUp, connect.CodeFailedPrecondition, "TOTP not set up, call SetupTOTP first")
		}
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get TOTP status")
	}

	if totpRecord.Enabled {
		return nil, apiErrorCtx(ctx, ErrTOTPAlreadyEnabled, connect.CodeFailedPrecondition, "TOTP is already enabled")
	}

	// Decrypt secret and validate code
	secret, err := h.encryptor.Decrypt(totpRecord.SecretEncrypted)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to decrypt TOTP secret")
	}

	if !totp.ValidateCode(req.Msg.Code, secret) {
		return connect.NewResponse(&pm.VerifyTOTPResponse{Success: false}), nil
	}

	// Mark TOTP as verified and enabled
	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "totp",
		StreamID:   userCtx.ID,
		EventType:  "TOTPVerified",
		Data:       map[string]any{},
		ActorType:  "user",
		ActorID:    userCtx.ID,
	}, "failed to verify TOTP"); err != nil {
		return nil, err
	}

	return connect.NewResponse(&pm.VerifyTOTPResponse{Success: true}), nil
}

// DisableTOTP disables TOTP for the current user (requires password confirmation).
func (h *TOTPHandler) DisableTOTP(ctx context.Context, req *connect.Request[pm.DisableTOTPRequest]) (*connect.Response[pm.DisableTOTPResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	// Verify password
	user, err := h.store.Queries().GetUserByID(ctx, userCtx.ID)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get user")
	}

	if !user.HasPassword {
		return nil, apiErrorCtx(ctx, ErrTOTPSSONotAllowed, connect.CodeFailedPrecondition, "cannot disable TOTP for accounts using federated login (SSO); contact an administrator")
	}

	if !auth.VerifyPassword(req.Msg.Password, derefPasswordHash(user.PasswordHash)) {
		return nil, apiErrorCtx(ctx, ErrPasswordIncorrect, connect.CodeUnauthenticated, "invalid password")
	}

	// Check TOTP is enabled
	if !user.TotpEnabled {
		return nil, apiErrorCtx(ctx, ErrTOTPNotEnabled, connect.CodeFailedPrecondition, "TOTP is not enabled")
	}

	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "totp",
		StreamID:   userCtx.ID,
		EventType:  "TOTPDisabled",
		Data:       map[string]any{},
		ActorType:  "user",
		ActorID:    userCtx.ID,
	}, "failed to disable TOTP"); err != nil {
		return nil, err
	}

	return connect.NewResponse(&pm.DisableTOTPResponse{}), nil
}

// AdminDisableUserTOTP disables TOTP for another user (admin only, no password required).
func (h *TOTPHandler) AdminDisableUserTOTP(ctx context.Context, req *connect.Request[pm.AdminDisableUserTOTPRequest]) (*connect.Response[pm.AdminDisableUserTOTPResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	targetUserID := req.Msg.UserId

	// Check target user exists and has TOTP enabled
	user, err := h.store.Queries().GetUserByID(ctx, targetUserID)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrUserNotFound, "user not found")
	}

	if !user.TotpEnabled {
		return nil, apiErrorCtx(ctx, ErrTOTPNotEnabled, connect.CodeFailedPrecondition, "TOTP is not enabled for this user")
	}

	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "totp",
		StreamID:   targetUserID,
		EventType:  "TOTPDisabled",
		Data:       map[string]any{"admin": true},
		ActorType:  "user",
		ActorID:    userCtx.ID,
	}, "failed to disable TOTP"); err != nil {
		return nil, err
	}

	return connect.NewResponse(&pm.AdminDisableUserTOTPResponse{}), nil
}

// GetTOTPStatus returns whether TOTP is enabled and how many backup codes remain.
func (h *TOTPHandler) GetTOTPStatus(ctx context.Context, req *connect.Request[pm.GetTOTPStatusRequest]) (*connect.Response[pm.GetTOTPStatusResponse], error) {
	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	status, err := h.store.Queries().GetTOTPStatus(ctx, userCtx.ID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return connect.NewResponse(&pm.GetTOTPStatusResponse{
				Enabled:              false,
				BackupCodesRemaining: 0,
			}), nil
		}
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get TOTP status")
	}

	return connect.NewResponse(&pm.GetTOTPStatusResponse{
		Enabled:              status.Enabled,
		BackupCodesRemaining: status.BackupCodesRemaining,
	}), nil
}

// RegenerateBackupCodes generates new backup codes (requires password confirmation).
func (h *TOTPHandler) RegenerateBackupCodes(ctx context.Context, req *connect.Request[pm.RegenerateBackupCodesRequest]) (*connect.Response[pm.RegenerateBackupCodesResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	// Verify password
	user, err := h.store.Queries().GetUserByID(ctx, userCtx.ID)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get user")
	}

	if !user.HasPassword {
		return nil, apiErrorCtx(ctx, ErrTOTPSSONotAllowed, connect.CodeFailedPrecondition, "cannot regenerate backup codes for accounts using federated login (SSO); contact an administrator")
	}

	if !auth.VerifyPassword(req.Msg.Password, derefPasswordHash(user.PasswordHash)) {
		return nil, apiErrorCtx(ctx, ErrPasswordIncorrect, connect.CodeUnauthenticated, "invalid password")
	}

	if !user.TotpEnabled {
		return nil, apiErrorCtx(ctx, ErrTOTPNotEnabled, connect.CodeFailedPrecondition, "TOTP is not enabled")
	}

	// Generate new backup codes
	codes, hashes, err := totp.GenerateBackupCodes()
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to generate backup codes")
	}

	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "totp",
		StreamID:   userCtx.ID,
		EventType:  "TOTPBackupCodesRegenerated",
		Data: map[string]any{
			"backup_codes_hash": hashes,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	}, "failed to regenerate backup codes"); err != nil {
		return nil, err
	}

	return connect.NewResponse(&pm.RegenerateBackupCodesResponse{
		BackupCodes: codes,
	}), nil
}

// VerifyLoginTOTP validates a TOTP code during the login flow (after password auth).
func (h *TOTPHandler) VerifyLoginTOTP(ctx context.Context, req *connect.Request[pm.VerifyLoginTOTPRequest]) (*connect.Response[pm.VerifyLoginTOTPResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	// Validate the challenge token
	claims, err := h.jwtManager.ValidateToken(req.Msg.Challenge, auth.TokenTypeTOTPChallenge)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrTOTPChallengeExpired, connect.CodeFailedPrecondition, "invalid or expired TOTP challenge")
	}

	// Get TOTP record
	totpRecord, err := h.store.Queries().GetTOTPByUserID(ctx, claims.UserID)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get TOTP data")
	}

	if !totpRecord.Enabled {
		return nil, apiErrorCtx(ctx, ErrTOTPNotEnabled, connect.CodeFailedPrecondition, "TOTP is not enabled")
	}

	// Decrypt secret
	secret, err := h.encryptor.Decrypt(totpRecord.SecretEncrypted)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to decrypt TOTP secret")
	}

	// Try TOTP code first (6 digits)
	codeValid := false
	if len(req.Msg.Code) == 6 {
		codeValid = totp.ValidateCode(req.Msg.Code, secret)
	}

	// If not a valid TOTP code, try backup code
	if !codeValid {
		idx := totp.VerifyBackupCode(req.Msg.Code, totpRecord.BackupCodesHash, totpRecord.BackupCodesUsed)
		if idx >= 0 {
			codeValid = true
			// Mark backup code as used. This is a primary CQRS
			// mutation — the projection reads this event to know
			// which codes are still valid. If the event fails to
			// persist, the code is NOT consumed and can be used
			// again (double-spend). Fail the RPC so the caller
			// retries rather than silently leaving the code valid.
			if err := h.store.AppendEvent(ctx, store.Event{
				StreamType: "totp",
				StreamID:   claims.UserID,
				EventType:  "TOTPBackupCodeUsed",
				Data:       map[string]any{"index": idx},
				ActorType:  "user",
				ActorID:    claims.UserID,
			}); err != nil {
				h.logger.Error("failed to consume backup code",
					"user_id", claims.UserID, "index", idx, "error", err)
				return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal,
					"failed to consume backup code")
			}
			h.logger.Debug("event appended",
				"request_id", middleware.RequestIDFromContext(ctx),
				"stream_type", "totp",
				"stream_id", claims.UserID,
				"event_type", "TOTPBackupCodeUsed",
			)
		}
	}

	if !codeValid {
		return nil, apiErrorCtx(ctx, ErrTOTPInvalid, connect.CodeInvalidArgument, "invalid TOTP code")
	}

	// Check user status
	info, err := h.store.Queries().GetUserSessionInfo(ctx, claims.UserID)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrUserNotFound, connect.CodeUnauthenticated, "user not found")
	}
	if info.IsDeleted || info.Disabled {
		return nil, apiErrorCtx(ctx, ErrNotAuthenticated, connect.CodeUnauthenticated, "account is disabled")
	}
	if info.SessionVersion != claims.SessionVersion {
		return nil, apiErrorCtx(ctx, ErrTokenExpired, connect.CodeUnauthenticated, "session invalidated, please log in again")
	}

	// Resolve permissions and generate real tokens
	permissions, err := h.store.Queries().GetUserPermissionsWithGroups(ctx, claims.UserID)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to resolve permissions")
	}

	tokens, err := h.jwtManager.GenerateTokens(claims.UserID, claims.Email, permissions, claims.SessionVersion)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to generate tokens")
	}

	// Emit login event
	if err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "user",
		StreamID:   claims.UserID,
		EventType:  "UserLoggedIn",
		Data:       map[string]any{},
		ActorType:  "user",
		ActorID:    claims.UserID,
	}); err != nil {
		h.logger.Warn("failed to append UserLoggedIn event", "user_id", claims.UserID, "error", err)
	} else {
		h.logger.Debug("event appended",
			"request_id", middleware.RequestIDFromContext(ctx),
			"stream_type", "user",
			"stream_id", claims.UserID,
			"event_type", "UserLoggedIn",
		)
	}

	// Get full user for response
	user, err := h.store.Queries().GetUserByID(ctx, claims.UserID)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get user")
	}

	protoUser := userToProto(user)
	if roles, err := h.store.Queries().GetUserRoles(ctx, user.ID); err == nil {
		for _, r := range roles {
			protoUser.Roles = append(protoUser.Roles, roleToProto(r))
		}
	}

	return connect.NewResponse(&pm.VerifyLoginTOTPResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		ExpiresAt:    timestamppb.New(tokens.ExpiresAt),
		User:         protoUser,
	}), nil
}
