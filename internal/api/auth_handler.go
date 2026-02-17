// Package api provides Connect-RPC handlers for the control server.
package api

import (
	"context"
	"errors"
	"time"

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

	if !auth.VerifyPassword(req.Msg.Password, user.PasswordHash) {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("invalid credentials"))
	}

	if user.Disabled {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("account is disabled"))
	}

	tokens, err := h.jwtManager.GenerateTokens(user.ID, user.Email, user.Role, user.SessionVersion)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to generate tokens"))
	}

	// Emit UserLoggedIn event for auditing (non-blocking, don't fail login)
	_ = h.store.AppendEvent(ctx, store.Event{
		StreamType: "user",
		StreamID:   user.ID,
		EventType:  "UserLoggedIn",
		Data:       map[string]any{},
		ActorType:  "user",
		ActorID:    user.ID,
	})

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

	// Set httpOnly cookies with the tokens
	secure := auth.IsSecureRequest(req.Header())
	refreshExpiry := time.Now().Add(7 * 24 * time.Hour)
	auth.SetTokenCookies(resp.Header(), tokens, refreshExpiry, secure)

	return resp, nil
}

// RefreshToken refreshes an access token and rotates the refresh token.
func (h *AuthHandler) RefreshToken(ctx context.Context, req *connect.Request[pm.RefreshTokenRequest]) (*connect.Response[pm.RefreshTokenResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	// Read refresh token from request body, falling back to cookie
	refreshToken := req.Msg.RefreshToken
	if refreshToken == "" {
		refreshToken = auth.CookieFromHeader(req.Header(), auth.RefreshTokenCookie)
	}
	if refreshToken == "" {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("missing refresh token"))
	}

	// Check if the refresh token has been revoked
	isRevoked := func(jti string) (bool, error) {
		return h.store.Queries().IsTokenRevoked(ctx, jti)
	}

	result, err := h.jwtManager.RefreshAccessToken(refreshToken, isRevoked)
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

	// Revoke the old refresh token to prevent reuse
	if result.OldJTI != "" {
		_ = h.store.Queries().RevokeToken(ctx, generated.RevokeTokenParams{
			Jti:       result.OldJTI,
			ExpiresAt: pgtype.Timestamptz{Time: result.OldExp, Valid: true},
		})
	}

	resp := connect.NewResponse(&pm.RefreshTokenResponse{
		AccessToken:  result.Tokens.AccessToken,
		ExpiresAt:    timestamppb.New(result.Tokens.ExpiresAt),
		RefreshToken: result.Tokens.RefreshToken,
	})

	// Set httpOnly cookies with the new tokens
	secure := auth.IsSecureRequest(req.Header())
	refreshExpiry := time.Now().Add(7 * 24 * time.Hour)
	auth.SetTokenCookies(resp.Header(), result.Tokens, refreshExpiry, secure)

	return resp, nil
}

// Logout revokes the refresh token so it can no longer be used.
func (h *AuthHandler) Logout(ctx context.Context, req *connect.Request[pm.LogoutRequest]) (*connect.Response[pm.LogoutResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	// Read refresh token from request body, falling back to cookie
	refreshToken := req.Msg.RefreshToken
	if refreshToken == "" {
		refreshToken = auth.CookieFromHeader(req.Header(), auth.RefreshTokenCookie)
	}

	if refreshToken != "" {
		claims, err := h.jwtManager.ValidateRefreshToken(refreshToken)
		if err == nil && claims.ID != "" {
			_ = h.store.Queries().RevokeToken(ctx, generated.RevokeTokenParams{
				Jti:       claims.ID,
				ExpiresAt: pgtype.Timestamptz{Time: claims.ExpiresAt.Time, Valid: true},
			})
		}
	}

	resp := connect.NewResponse(&pm.LogoutResponse{})

	// Clear token cookies
	secure := auth.IsSecureRequest(req.Header())
	auth.ClearTokenCookies(resp.Header(), secure)

	return resp, nil
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
