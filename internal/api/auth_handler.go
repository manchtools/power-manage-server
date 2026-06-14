// Package api provides Connect-RPC handlers for the control server.
package api

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/middleware"
	"github.com/manchtools/power-manage/server/internal/store"
)

// Per-account login throttle: at most loginAccountFailLimit FAILED password
// attempts per account within loginAccountFailWindow, independent of source IP.
// The interceptor's IP limiter is bypassable by rotating IPs, so a targeted
// admin needs an account-keyed ceiling too. Only FAILURES are counted, so a
// legitimate user's normal/successful logins never accrue toward it.
const (
	loginAccountFailLimit  = 10
	loginAccountFailWindow = 15 * time.Minute
)

// AuthHandler handles authentication RPCs.
type AuthHandler struct {
	store               *store.Store
	logger              *slog.Logger
	jwtManager          *auth.JWTManager
	passwordAuthEnabled bool
	// loginAccountLimiter throttles FAILED password attempts per account
	// (keyed by normalised email), closing the IP-rotation bypass on the
	// interceptor's per-IP login limiter.
	loginAccountLimiter *auth.RateLimiter
}

// NewAuthHandler creates a new auth handler. The passwordAuthEnabled flag
// is the global `CONTROL_PASSWORD_AUTH_ENABLED` operator switch. When
// false, Login rejects every password attempt regardless of the per-user
// HasPassword column — previous revs only gated the SSO UI's auth-method
// list on this flag, leaving the RPC itself open to direct password
// attempts against accounts that still had a password hash on disk.
func NewAuthHandler(st *store.Store, logger *slog.Logger, jwtManager *auth.JWTManager, passwordAuthEnabled bool) *AuthHandler {
	return &AuthHandler{
		store:               st,
		logger:              logger,
		jwtManager:          jwtManager,
		passwordAuthEnabled: passwordAuthEnabled,
		loginAccountLimiter: auth.NewRateLimiter(loginAccountFailLimit, loginAccountFailWindow),
	}
}

// Login authenticates a user and returns tokens.
func (h *AuthHandler) Login(ctx context.Context, req *connect.Request[pm.LoginRequest]) (*connect.Response[pm.LoginResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	// Global password-auth switch — enforced BEFORE the user lookup so a
	// burned bcrypt cycle doesn't leak account existence via timing when
	// the operator has disabled password login entirely.
	if !h.passwordAuthEnabled {
		auth.VerifyPassword(req.Msg.Password, auth.DummyHash)
		return nil, apiErrorCtx(ctx, ErrPasswordLoginDisabled, connect.CodeUnauthenticated, "password login is disabled on this server")
	}

	// Per-account brute-force ceiling. Checked BEFORE the user lookup so the
	// response is identical whether or not the account exists (no enumeration
	// signal) and so a blocked account spends no bcrypt cycles. Keyed by
	// normalised email; only failed attempts are counted (below), so it never
	// throttles a legitimate user's successful logins. This closes the
	// IP-rotation bypass on the interceptor's per-IP login limiter (#381).
	acctKey := "login:" + strings.ToLower(strings.TrimSpace(req.Msg.Email))
	if h.loginAccountLimiter.Blocked(acctKey) {
		return nil, apiErrorCtx(ctx, ErrRateLimited, connect.CodeResourceExhausted, "too many failed login attempts for this account, try again later")
	}

	user, err := h.store.Repos().User.GetByEmail(ctx, req.Msg.Email)
	if err != nil {
		if store.IsNotFound(err) {
			// Perform a dummy bcrypt comparison to prevent timing-based user enumeration
			auth.VerifyPassword(req.Msg.Password, auth.DummyHash)
			// Count the failure for the per-account ceiling. Recording for a
			// non-existent email too keeps the behaviour identical to a real
			// account (no enumeration), and an attacker spraying one address is
			// still throttled.
			h.loginAccountLimiter.Allow(acctKey)
			return nil, apiErrorCtx(ctx, ErrInvalidCredentials, connect.CodeUnauthenticated, "invalid credentials")
		}
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to look up user")
	}

	// Check password eligibility. An SSO-only account (no password) must be
	// INDISTINGUISHABLE from a non-existent account or a wrong password to an
	// unauthenticated caller — same timing (dummy bcrypt), same per-account
	// throttle accounting, same generic error. The prior fast-path + distinct
	// "password login is not available" error was a user-enumeration oracle
	// (audit). The login UI learns the right method from the (now rate-limited)
	// ListAuthMethods, not from this error.
	if !user.HasPassword {
		auth.VerifyPassword(req.Msg.Password, auth.DummyHash)
		h.loginAccountLimiter.Allow(acctKey)
		return nil, apiErrorCtx(ctx, ErrInvalidCredentials, connect.CodeUnauthenticated, "invalid credentials")
	}

	// A linked provider that disables password login gets the SAME enumeration-
	// safe response — no provider-name disclosure to an unauthenticated caller.
	// Fail CLOSED on a query error: the prior `if err == nil` swallowed a
	// transient DB failure and fell through to password verification, letting a
	// provider-disabled account authenticate. A lookup error denies login.
	disablingProviders, err := h.store.Queries().GetLinkedProvidersDisablingPassword(ctx, user.ID)
	if err != nil {
		h.logger.Error("failed to check provider password restrictions", "user_id", user.ID, "error", err)
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to verify login eligibility")
	}
	if len(disablingProviders) > 0 {
		auth.VerifyPassword(req.Msg.Password, auth.DummyHash)
		h.loginAccountLimiter.Allow(acctKey)
		return nil, apiErrorCtx(ctx, ErrInvalidCredentials, connect.CodeUnauthenticated, "invalid credentials")
	}

	if !auth.VerifyPassword(req.Msg.Password, derefPasswordHash(user.PasswordHash)) {
		h.loginAccountLimiter.Allow(acctKey) // count the failed attempt
		return nil, apiErrorCtx(ctx, ErrInvalidCredentials, connect.CodeUnauthenticated, "invalid credentials")
	}

	// WS11 #11: a disabled account with the correct password must be
	// INDISTINGUISHABLE from a wrong password to a credential holder — a
	// distinct "account is disabled" / CodePermissionDenied response is a
	// user-enumeration oracle. Collapse it into the generic
	// invalid-credentials path and account the failure toward the per-account
	// ceiling like the other rejection branches. (The post-2FA disabled check
	// in totp_handler.VerifyLoginTOTP intentionally keeps the explicit error —
	// the caller has already proven the second factor there.)
	if user.Disabled {
		h.loginAccountLimiter.Allow(acctKey)
		return nil, apiErrorCtx(ctx, ErrInvalidCredentials, connect.CodeUnauthenticated, "invalid credentials")
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

	// Resolve permissions + scoped grants from DB and embed in JWT
	permissions, err := h.store.Repos().User.Permissions(ctx, user.ID)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to resolve permissions")
	}
	scopedGrants, err := resolveScopedGrants(ctx, h.store.Repos().User, user.ID)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to resolve scoped grants")
	}

	tokens, err := h.jwtManager.GenerateTokens(user.ID, user.Email, permissions, scopedGrants, user.SessionVersion)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to generate tokens")
	}

	// Emit UserLoggedIn event for auditing (non-blocking, don't fail login)
	if err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "user",
		StreamID:   user.ID,
		EventType:  string(eventtypes.UserLoggedIn),
		Data:       map[string]any{},
		ActorType:  "user",
		ActorID:    user.ID,
	}); err != nil {
		h.logger.Error("AUDIT GAP: failed to append UserLoggedIn event; password login proceeded without audit record",
			"user_id", user.ID, "error", err)
	} else {
		h.logger.Debug("event appended",
			"request_id", middleware.RequestIDFromContext(ctx),
			"stream_type", "user",
			"stream_id", user.ID,
			"event_type", "UserLoggedIn",
		)
	}

	h.logger.Info("user logged in", "user_id", user.ID)

	protoUser := userToProto(user)
	// Populate user roles
	if roles, err := h.store.Repos().Role.ListUserRoles(ctx, user.ID); err == nil {
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
		return h.store.Repos().RevokedToken.IsRevoked(ctx, jti)
	}

	result, err := h.jwtManager.ValidateRefreshToken(refreshToken, isRevoked)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrTokenExpired, connect.CodeUnauthenticated, "invalid or expired refresh token")
	}

	// Check user status (disabled, deleted) and session version before issuing new tokens
	info, err := h.store.Repos().User.SessionInfo(ctx, result.Claims.UserID)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrUserNotFound, connect.CodeUnauthenticated, "user not found")
	}
	if info.IsDeleted || info.Disabled {
		return nil, apiErrorCtx(ctx, ErrNotAuthenticated, connect.CodeUnauthenticated, "account is disabled or deleted")
	}
	if info.SessionVersion != result.Claims.SessionVersion {
		return nil, apiErrorCtx(ctx, ErrTokenExpired, connect.CodeUnauthenticated, "session invalidated, please log in again")
	}

	// Atomically revoke the old refresh token BEFORE generating new tokens.
	// RevokeToken uses INSERT ... ON CONFLICT DO NOTHING RETURNING jti, so it
	// reports not-found (recognized via store.IsNotFound) when the token was already revoked by a concurrent
	// request. This prevents a race where two concurrent RefreshToken calls
	// with the same token both succeed.
	if result.OldJTI != "" {
		_, err := h.store.Repos().RevokedToken.Revoke(ctx, result.OldJTI, result.OldExp)
		if err != nil {
			return nil, apiErrorCtx(ctx, ErrTokenExpired, connect.CodeUnauthenticated, "refresh token already used")
		}
	}

	// Resolve fresh permissions from DB
	permissions, err := h.store.Repos().User.Permissions(ctx, result.Claims.UserID)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to resolve permissions")
	}
	scopedGrants, err := resolveScopedGrants(ctx, h.store.Repos().User, result.Claims.UserID)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to resolve scoped grants")
	}

	// Generate new token pair with fresh permissions + scoped grants
	tokens, err := h.jwtManager.GenerateTokens(result.Claims.UserID, result.Claims.Email, permissions, scopedGrants, result.Claims.SessionVersion)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to generate tokens")
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
			if _, err := h.store.Repos().RevokedToken.Revoke(ctx, claims.ID, claims.ExpiresAt.Time); err != nil {
				h.logger.Warn("failed to revoke token on logout", "jti", claims.ID, "error", err)
			}
		}
	}

	return connect.NewResponse(&pm.LogoutResponse{}), nil
}

// GetCurrentUser returns the current authenticated user.
func (h *AuthHandler) GetCurrentUser(ctx context.Context, req *connect.Request[pm.GetCurrentUserRequest]) (*connect.Response[pm.GetCurrentUserResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	user, err := h.store.Repos().User.Get(ctx, userCtx.ID)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrUserNotFound, "user not found")
	}

	protoUser := userToProto(user)
	// Populate user roles
	if roles, err := h.store.Repos().Role.ListUserRoles(ctx, user.ID); err == nil {
		for _, r := range roles {
			protoUser.Roles = append(protoUser.Roles, roleToProto(r))
		}
	}

	return connect.NewResponse(&pm.GetCurrentUserResponse{
		User: protoUser,
	}), nil
}

// resolveScopedGrants resolves the user's (permission, scope) grants and
// maps them to the auth-layer ScopedGrant shape embedded in the JWT
// `sgrants` claim. Empty result (no scoped grants) is fine — the claim
// is omitempty, so an unscoped user's token is unchanged (#7 S2b).
func resolveScopedGrants(ctx context.Context, users store.UserRepo, userID string) ([]auth.ScopedGrant, error) {
	grants, err := users.ScopedGrants(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]auth.ScopedGrant, len(grants))
	for i, g := range grants {
		out[i] = auth.ScopedGrant{Permission: g.Permission, ScopeKind: g.ScopeKind, ScopeID: g.ScopeID}
	}
	return out, nil
}
