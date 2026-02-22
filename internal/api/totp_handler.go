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
	"github.com/manchtools/power-manage/server/internal/store"
)

// TOTPHandler handles TOTP two-factor authentication RPCs.
type TOTPHandler struct {
	store      *store.Store
	jwtManager *auth.JWTManager
	encryptor  *crypto.Encryptor
	issuer     string
}

// NewTOTPHandler creates a new TOTP handler.
func NewTOTPHandler(st *store.Store, jwtManager *auth.JWTManager, enc *crypto.Encryptor, issuer string) *TOTPHandler {
	if issuer == "" {
		issuer = totp.DefaultIssuer
	}
	return &TOTPHandler{
		store:      st,
		jwtManager: jwtManager,
		encryptor:  enc,
		issuer:     issuer,
	}
}

// SetupTOTP generates a new TOTP secret and backup codes for the current user.
func (h *TOTPHandler) SetupTOTP(ctx context.Context, req *connect.Request[pm.SetupTOTPRequest]) (*connect.Response[pm.SetupTOTPResponse], error) {
	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}

	// Generate TOTP key
	key, err := totp.GenerateKey(h.issuer, userCtx.Email)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to generate TOTP key"))
	}

	// Generate backup codes
	codes, hashes, err := totp.GenerateBackupCodes()
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to generate backup codes"))
	}

	// Encrypt the TOTP secret
	encryptedSecret, err := h.encryptor.Encrypt(key.Secret())
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to encrypt TOTP secret"))
	}

	// Store via event
	hashesAny := make([]any, len(hashes))
	for i, h := range hashes {
		hashesAny[i] = h
	}

	err = h.store.AppendEvent(ctx, store.Event{
		StreamType: "totp",
		StreamID:   userCtx.ID,
		EventType:  "TOTPSetupInitiated",
		Data: map[string]any{
			"secret_encrypted":  encryptedSecret,
			"backup_codes_hash": hashes,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to save TOTP setup"))
	}

	return connect.NewResponse(&pm.SetupTOTPResponse{
		Secret:      key.Secret(),
		QrUri:       key.URL(),
		BackupCodes: codes,
	}), nil
}

// VerifyTOTP confirms TOTP setup by validating a code from the user's authenticator app.
func (h *TOTPHandler) VerifyTOTP(ctx context.Context, req *connect.Request[pm.VerifyTOTPRequest]) (*connect.Response[pm.VerifyTOTPResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}

	// Get pending TOTP setup
	totpRecord, err := h.store.Queries().GetTOTPByUserID(ctx, userCtx.ID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("TOTP not set up, call SetupTOTP first"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get TOTP status"))
	}

	if totpRecord.Enabled {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("TOTP is already enabled"))
	}

	// Decrypt secret and validate code
	secret, err := h.encryptor.Decrypt(totpRecord.SecretEncrypted)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to decrypt TOTP secret"))
	}

	if !totp.ValidateCode(req.Msg.Code, secret) {
		return connect.NewResponse(&pm.VerifyTOTPResponse{Success: false}), nil
	}

	// Mark TOTP as verified and enabled
	err = h.store.AppendEvent(ctx, store.Event{
		StreamType: "totp",
		StreamID:   userCtx.ID,
		EventType:  "TOTPVerified",
		Data:       map[string]any{},
		ActorType:  "user",
		ActorID:    userCtx.ID,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to verify TOTP"))
	}

	return connect.NewResponse(&pm.VerifyTOTPResponse{Success: true}), nil
}

// DisableTOTP disables TOTP for the current user (requires password confirmation).
func (h *TOTPHandler) DisableTOTP(ctx context.Context, req *connect.Request[pm.DisableTOTPRequest]) (*connect.Response[pm.DisableTOTPResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}

	// Verify password
	user, err := h.store.Queries().GetUserByID(ctx, userCtx.ID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get user"))
	}

	if !auth.VerifyPassword(req.Msg.Password, derefPasswordHash(user.PasswordHash)) {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("invalid password"))
	}

	// Check TOTP is enabled
	if !user.TotpEnabled {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("TOTP is not enabled"))
	}

	err = h.store.AppendEvent(ctx, store.Event{
		StreamType: "totp",
		StreamID:   userCtx.ID,
		EventType:  "TOTPDisabled",
		Data:       map[string]any{},
		ActorType:  "user",
		ActorID:    userCtx.ID,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to disable TOTP"))
	}

	return connect.NewResponse(&pm.DisableTOTPResponse{}), nil
}

// GetTOTPStatus returns whether TOTP is enabled and how many backup codes remain.
func (h *TOTPHandler) GetTOTPStatus(ctx context.Context, req *connect.Request[pm.GetTOTPStatusRequest]) (*connect.Response[pm.GetTOTPStatusResponse], error) {
	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}

	status, err := h.store.Queries().GetTOTPStatus(ctx, userCtx.ID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return connect.NewResponse(&pm.GetTOTPStatusResponse{
				Enabled:              false,
				BackupCodesRemaining: 0,
			}), nil
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get TOTP status"))
	}

	return connect.NewResponse(&pm.GetTOTPStatusResponse{
		Enabled:              status.Enabled,
		BackupCodesRemaining: status.BackupCodesRemaining,
	}), nil
}

// RegenerateBackupCodes generates new backup codes (requires password confirmation).
func (h *TOTPHandler) RegenerateBackupCodes(ctx context.Context, req *connect.Request[pm.RegenerateBackupCodesRequest]) (*connect.Response[pm.RegenerateBackupCodesResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}

	// Verify password
	user, err := h.store.Queries().GetUserByID(ctx, userCtx.ID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get user"))
	}

	if !auth.VerifyPassword(req.Msg.Password, derefPasswordHash(user.PasswordHash)) {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("invalid password"))
	}

	if !user.TotpEnabled {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("TOTP is not enabled"))
	}

	// Generate new backup codes
	codes, hashes, err := totp.GenerateBackupCodes()
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to generate backup codes"))
	}

	err = h.store.AppendEvent(ctx, store.Event{
		StreamType: "totp",
		StreamID:   userCtx.ID,
		EventType:  "TOTPBackupCodesRegenerated",
		Data: map[string]any{
			"backup_codes_hash": hashes,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to regenerate backup codes"))
	}

	return connect.NewResponse(&pm.RegenerateBackupCodesResponse{
		BackupCodes: codes,
	}), nil
}

// VerifyLoginTOTP validates a TOTP code during the login flow (after password auth).
func (h *TOTPHandler) VerifyLoginTOTP(ctx context.Context, req *connect.Request[pm.VerifyLoginTOTPRequest]) (*connect.Response[pm.VerifyLoginTOTPResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	// Validate the challenge token
	claims, err := h.jwtManager.ValidateToken(req.Msg.Challenge, auth.TokenTypeTOTPChallenge)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("invalid or expired TOTP challenge"))
	}

	// Get TOTP record
	totpRecord, err := h.store.Queries().GetTOTPByUserID(ctx, claims.UserID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get TOTP data"))
	}

	if !totpRecord.Enabled {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("TOTP is not enabled"))
	}

	// Decrypt secret
	secret, err := h.encryptor.Decrypt(totpRecord.SecretEncrypted)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to decrypt TOTP secret"))
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
			// Mark backup code as used
			if err := h.store.AppendEvent(ctx, store.Event{
				StreamType: "totp",
				StreamID:   claims.UserID,
				EventType:  "TOTPBackupCodeUsed",
				Data:       map[string]any{"index": idx},
				ActorType:  "user",
				ActorID:    claims.UserID,
			}); err != nil {
				slog.Warn("failed to append TOTPBackupCodeUsed event", "user_id", claims.UserID, "error", err)
			}
		}
	}

	if !codeValid {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("invalid TOTP code"))
	}

	// Check user status
	info, err := h.store.Queries().GetUserSessionInfo(ctx, claims.UserID)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("user not found"))
	}
	if info.IsDeleted || info.Disabled {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("account is disabled or deleted"))
	}
	if info.SessionVersion != claims.SessionVersion {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("session invalidated, please log in again"))
	}

	// Resolve permissions and generate real tokens
	permissions, err := h.store.Queries().GetUserPermissionsWithGroups(ctx, claims.UserID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to resolve permissions"))
	}

	tokens, err := h.jwtManager.GenerateTokens(claims.UserID, claims.Email, permissions, claims.SessionVersion)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to generate tokens"))
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
		slog.Warn("failed to append UserLoggedIn event", "user_id", claims.UserID, "error", err)
	}

	// Get full user for response
	user, err := h.store.Queries().GetUserByID(ctx, claims.UserID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get user"))
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
