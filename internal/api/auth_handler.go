// Package api provides Connect-RPC handlers for the control server.
package api

import (
	"context"
	"errors"
	"log/slog"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/protobuf/types/known/timestamppb"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/middleware"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/store/generated"
)

// AuthHandler handles authentication RPCs.
type AuthHandler struct {
	store      *store.Store
	logger     *slog.Logger
	jwtManager *auth.JWTManager
}

// NewAuthHandler creates a new auth handler.
func NewAuthHandler(st *store.Store, logger *slog.Logger, jwtManager *auth.JWTManager) *AuthHandler {
	return &AuthHandler{
		store:      st,
		logger:     logger,
		jwtManager: jwtManager,
	}
}

// Login authenticates a user and returns tokens.
func (h *AuthHandler) Login(ctx context.Context, req *connect.Request[pm.LoginRequest]) (*connect.Response[pm.LoginResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	user, err := h.store.Queries().GetUserByEmail(ctx, req.Msg.Email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Perform a dummy bcrypt comparison to prevent timing-based user enumeration
			auth.VerifyPassword(req.Msg.Password, auth.DummyHash)
			return nil, apiErrorCtx(ctx, ErrInvalidCredentials, connect.CodeUnauthenticated, "invalid credentials")
		}
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to look up user")
	}

	// Check password eligibility
	if !user.HasPassword {
		return nil, apiErrorCtx(ctx, ErrPasswordLoginDisabled, connect.CodeUnauthenticated, "password login is not available for this account")
	}

	// Check if any linked provider disables password login
	disablingProviders, err := h.store.Queries().GetLinkedProvidersDisablingPassword(ctx, user.ID)
	if err == nil && len(disablingProviders) > 0 {
		return nil, apiErrorCtx(ctx, ErrPasswordLoginDisabled, connect.CodeUnauthenticated, "password login is disabled; use "+disablingProviders[0].Name+" to sign in")
	}

	if !auth.VerifyPassword(req.Msg.Password, derefPasswordHash(user.PasswordHash)) {
		return nil, apiErrorCtx(ctx, ErrInvalidCredentials, connect.CodeUnauthenticated, "invalid credentials")
	}

	if user.Disabled {
		return nil, apiErrorCtx(ctx, ErrNotAuthenticated, connect.CodePermissionDenied, "account is disabled")
	}

	// If TOTP is enabled, return a challenge instead of tokens
	if user.TotpEnabled {
		challenge, err := h.jwtManager.GenerateTOTPChallenge(user.ID, user.Email, user.SessionVersion)
		if err != nil {
			return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to generate TOTP challenge")
		}
		return connect.NewResponse(&pm.LoginResponse{
			TotpRequired:  true,
			TotpChallenge: challenge,
		}), nil
	}

	// Resolve permissions from DB and embed in JWT
	permissions, err := h.store.Queries().GetUserPermissionsWithGroups(ctx, user.ID)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to resolve permissions")
	}

	tokens, err := h.jwtManager.GenerateTokens(user.ID, user.Email, permissions, user.SessionVersion)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to generate tokens")
	}

	// Emit UserLoggedIn event for auditing (non-blocking, don't fail login)
	if err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "user",
		StreamID:   user.ID,
		EventType:  "UserLoggedIn",
		Data:       map[string]any{},
		ActorType:  "user",
		ActorID:    user.ID,
	}); err != nil {
		h.logger.Warn("failed to append UserLoggedIn event", "user_id", user.ID, "error", err)
	} else {
		h.logger.Debug("event appended",
			"request_id", middleware.RequestIDFromContext(ctx),
			"stream_type", "user",
			"stream_id", user.ID,
			"event_type", "UserLoggedIn",
		)
	}

	h.logger.Info("user logged in", "user_id", user.ID, "email", user.Email)

	protoUser := userToProto(user)
	// Populate user roles
	if roles, err := h.store.Queries().GetUserRoles(ctx, user.ID); err == nil {
		for _, r := range roles {
			protoUser.Roles = append(protoUser.Roles, roleToProto(r))
		}
	}

	resp := connect.NewResponse(&pm.LoginResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		ExpiresAt:    timestamppb.New(tokens.ExpiresAt),
		User:         protoUser,
	})

	return resp, nil
}

// RefreshToken refreshes an access token and rotates the refresh token.
func (h *AuthHandler) RefreshToken(ctx context.Context, req *connect.Request[pm.RefreshTokenRequest]) (*connect.Response[pm.RefreshTokenResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	// Read refresh token from request body
	refreshToken := req.Msg.RefreshToken
	if refreshToken == "" {
		return nil, apiErrorCtx(ctx, ErrValidationFailed, connect.CodeUnauthenticated, "missing refresh token")
	}

	// Validate refresh token and check revocation
	isRevoked := func(jti string) (bool, error) {
		return h.store.Queries().IsTokenRevoked(ctx, jti)
	}

	result, err := h.jwtManager.ValidateRefreshToken(refreshToken, isRevoked)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrTokenExpired, connect.CodeUnauthenticated, "invalid or expired refresh token")
	}

	// Check user status (disabled, deleted) and session version before issuing new tokens
	info, err := h.store.Queries().GetUserSessionInfo(ctx, result.Claims.UserID)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrUserNotFound, connect.CodeUnauthenticated, "user not found")
	}
	if info.IsDeleted || info.Disabled {
		return nil, apiErrorCtx(ctx, ErrNotAuthenticated, connect.CodeUnauthenticated, "account is disabled or deleted")
	}
	if info.SessionVersion != result.Claims.SessionVersion {
		return nil, apiErrorCtx(ctx, ErrTokenExpired, connect.CodeUnauthenticated, "session invalidated, please log in again")
	}

	// Resolve fresh permissions from DB
	permissions, err := h.store.Queries().GetUserPermissionsWithGroups(ctx, result.Claims.UserID)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to resolve permissions")
	}

	// Generate new token pair with fresh permissions
	tokens, err := h.jwtManager.GenerateTokens(result.Claims.UserID, result.Claims.Email, permissions, result.Claims.SessionVersion)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to generate tokens")
	}

	// Revoke the old refresh token to prevent reuse
	if result.OldJTI != "" {
		if err := h.store.Queries().RevokeToken(ctx, generated.RevokeTokenParams{
			Jti:       result.OldJTI,
			ExpiresAt: pgtype.Timestamptz{Time: result.OldExp, Valid: true},
		}); err != nil {
			h.logger.Warn("failed to revoke old refresh token", "jti", result.OldJTI, "error", err)
		}
	}

	resp := connect.NewResponse(&pm.RefreshTokenResponse{
		AccessToken:  tokens.AccessToken,
		ExpiresAt:    timestamppb.New(tokens.ExpiresAt),
		RefreshToken: tokens.RefreshToken,
	})

	return resp, nil
}

// Logout revokes the refresh token so it can no longer be used.
func (h *AuthHandler) Logout(ctx context.Context, req *connect.Request[pm.LogoutRequest]) (*connect.Response[pm.LogoutResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	// Read refresh token from request body
	refreshToken := req.Msg.RefreshToken
	if refreshToken != "" {
		claims, err := h.jwtManager.ValidateToken(refreshToken, auth.TokenTypeRefresh)
		if err == nil && claims.ID != "" {
			if err := h.store.Queries().RevokeToken(ctx, generated.RevokeTokenParams{
				Jti:       claims.ID,
				ExpiresAt: pgtype.Timestamptz{Time: claims.ExpiresAt.Time, Valid: true},
			}); err != nil {
				h.logger.Warn("failed to revoke token on logout", "jti", claims.ID, "error", err)
			}
		}
	}

	return connect.NewResponse(&pm.LogoutResponse{}), nil
}

// GetCurrentUser returns the current authenticated user.
func (h *AuthHandler) GetCurrentUser(ctx context.Context, req *connect.Request[pm.GetCurrentUserRequest]) (*connect.Response[pm.GetCurrentUserResponse], error) {
	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, apiErrorCtx(ctx, ErrNotAuthenticated, connect.CodeUnauthenticated, "not authenticated")
	}

	user, err := h.store.Queries().GetUserByID(ctx, userCtx.ID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apiErrorCtx(ctx, ErrUserNotFound, connect.CodeNotFound, "user not found")
		}
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get user")
	}

	protoUser := userToProto(user)
	// Populate user roles
	if roles, err := h.store.Queries().GetUserRoles(ctx, user.ID); err == nil {
		for _, r := range roles {
			protoUser.Roles = append(protoUser.Roles, roleToProto(r))
		}
	}

	return connect.NewResponse(&pm.GetCurrentUserResponse{
		User: protoUser,
	}), nil
}
