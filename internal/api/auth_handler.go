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
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/store/generated"
)

// AuthHandler handles authentication RPCs.
type AuthHandler struct {
	store      *store.Store
	jwtManager *auth.JWTManager
}

// NewAuthHandler creates a new auth handler.
func NewAuthHandler(st *store.Store, jwtManager *auth.JWTManager) *AuthHandler {
	return &AuthHandler{
		store:      st,
		jwtManager: jwtManager,
	}
}

// Login authenticates a user and returns tokens.
func (h *AuthHandler) Login(ctx context.Context, req *connect.Request[pm.LoginRequest]) (*connect.Response[pm.LoginResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	user, err := h.store.Queries().GetUserByEmail(ctx, req.Msg.Email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Perform a dummy bcrypt comparison to prevent timing-based user enumeration
			auth.VerifyPassword(req.Msg.Password, auth.DummyHash)
			return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("invalid credentials"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to look up user"))
	}

	// Check password eligibility
	if !user.HasPassword {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("password login is not available for this account"))
	}

	// Check if any linked provider disables password login
	disablingProviders, err := h.store.Queries().GetLinkedProvidersDisablingPassword(ctx, user.ID)
	if err == nil && len(disablingProviders) > 0 {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("password login is disabled; use "+disablingProviders[0].Name+" to sign in"))
	}

	if !auth.VerifyPassword(req.Msg.Password, derefPasswordHash(user.PasswordHash)) {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("invalid credentials"))
	}

	if user.Disabled {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("account is disabled"))
	}

	// If TOTP is enabled, return a challenge instead of tokens
	if user.TotpEnabled {
		challenge, err := h.jwtManager.GenerateTOTPChallenge(user.ID, user.Email, user.SessionVersion)
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, errors.New("failed to generate TOTP challenge"))
		}
		return connect.NewResponse(&pm.LoginResponse{
			TotpRequired:  true,
			TotpChallenge: challenge,
		}), nil
	}

	// Resolve permissions from DB and embed in JWT
	permissions, err := h.store.Queries().GetUserPermissionsWithGroups(ctx, user.ID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to resolve permissions"))
	}

	tokens, err := h.jwtManager.GenerateTokens(user.ID, user.Email, permissions, user.SessionVersion)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to generate tokens"))
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
		slog.Warn("failed to append UserLoggedIn event", "user_id", user.ID, "error", err)
	}

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
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	// Read refresh token from request body
	refreshToken := req.Msg.RefreshToken
	if refreshToken == "" {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("missing refresh token"))
	}

	// Validate refresh token and check revocation
	isRevoked := func(jti string) (bool, error) {
		return h.store.Queries().IsTokenRevoked(ctx, jti)
	}

	result, err := h.jwtManager.ValidateRefreshToken(refreshToken, isRevoked)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("invalid or expired refresh token"))
	}

	// Check user status (disabled, deleted) and session version before issuing new tokens
	info, err := h.store.Queries().GetUserSessionInfo(ctx, result.Claims.UserID)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("user not found"))
	}
	if info.IsDeleted || info.Disabled {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("account is disabled or deleted"))
	}
	if info.SessionVersion != result.Claims.SessionVersion {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("session invalidated, please log in again"))
	}

	// Resolve fresh permissions from DB
	permissions, err := h.store.Queries().GetUserPermissionsWithGroups(ctx, result.Claims.UserID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to resolve permissions"))
	}

	// Generate new token pair with fresh permissions
	tokens, err := h.jwtManager.GenerateTokens(result.Claims.UserID, result.Claims.Email, permissions, result.Claims.SessionVersion)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to generate tokens"))
	}

	// Revoke the old refresh token to prevent reuse
	if result.OldJTI != "" {
		_ = h.store.Queries().RevokeToken(ctx, generated.RevokeTokenParams{
			Jti:       result.OldJTI,
			ExpiresAt: pgtype.Timestamptz{Time: result.OldExp, Valid: true},
		})
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
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	// Read refresh token from request body
	refreshToken := req.Msg.RefreshToken
	if refreshToken != "" {
		claims, err := h.jwtManager.ValidateToken(refreshToken, auth.TokenTypeRefresh)
		if err == nil && claims.ID != "" {
			_ = h.store.Queries().RevokeToken(ctx, generated.RevokeTokenParams{
				Jti:       claims.ID,
				ExpiresAt: pgtype.Timestamptz{Time: claims.ExpiresAt.Time, Valid: true},
			})
		}
	}

	return connect.NewResponse(&pm.LogoutResponse{}), nil
}

// GetCurrentUser returns the current authenticated user.
func (h *AuthHandler) GetCurrentUser(ctx context.Context, req *connect.Request[pm.GetCurrentUserRequest]) (*connect.Response[pm.GetCurrentUserResponse], error) {
	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}

	user, err := h.store.Queries().GetUserByID(ctx, userCtx.ID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("user not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get user"))
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
