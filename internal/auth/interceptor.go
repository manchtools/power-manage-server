package auth

import (
	"context"
	"errors"
	"strings"

	"connectrpc.com/connect"

	"github.com/manchtools/power-manage/server/internal/store"
)

// PublicProcedures are procedures that don't require authentication.
var PublicProcedures = map[string]bool{
	"/pm.v1.ControlService/Login":        true,
	"/pm.v1.ControlService/RefreshToken": true,
	"/pm.v1.ControlService/Logout":       true,
	"/pm.v1.ControlService/Register":     true,
}

// AuthInterceptor provides Connect-RPC authentication interceptor.
type AuthInterceptor struct {
	jwtManager      *JWTManager
	loginLimiter    *RateLimiter
	refreshLimiter  *RateLimiter
	registerLimiter *RateLimiter
}

// NewAuthInterceptor creates a new authentication interceptor.
func NewAuthInterceptor(jwtManager *JWTManager, loginLimiter, refreshLimiter, registerLimiter *RateLimiter) *AuthInterceptor {
	return &AuthInterceptor{jwtManager: jwtManager, loginLimiter: loginLimiter, refreshLimiter: refreshLimiter, registerLimiter: registerLimiter}
}

// WrapUnary implements connect.Interceptor.
func (i *AuthInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		procedure := req.Spec().Procedure

		// Rate limit login attempts by peer address
		if procedure == "/pm.v1.ControlService/Login" && i.loginLimiter != nil {
			ip := req.Peer().Addr
			if !i.loginLimiter.Allow(ip) {
				return nil, connect.NewError(connect.CodeResourceExhausted, errors.New("too many login attempts, try again later"))
			}
		}

		// Rate limit token refresh attempts by peer address
		if procedure == "/pm.v1.ControlService/RefreshToken" && i.refreshLimiter != nil {
			ip := req.Peer().Addr
			if !i.refreshLimiter.Allow(ip) {
				return nil, connect.NewError(connect.CodeResourceExhausted, errors.New("too many refresh attempts, try again later"))
			}
		}

		// Rate limit registration attempts by peer address
		if procedure == "/pm.v1.ControlService/Register" && i.registerLimiter != nil {
			ip := req.Peer().Addr
			if !i.registerLimiter.Allow(ip) {
				return nil, connect.NewError(connect.CodeResourceExhausted, errors.New("too many registration attempts, try again later"))
			}
		}

		// Skip auth for public procedures
		if PublicProcedures[procedure] {
			return next(ctx, req)
		}

		// Extract token from Authorization header or httpOnly cookie
		var tokenString string
		authHeader := req.Header().Get("Authorization")
		if authHeader != "" {
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
				return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("invalid authorization header format"))
			}
			tokenString = parts[1]
		} else {
			tokenString = CookieFromHeader(req.Header(), AccessTokenCookie)
		}
		if tokenString == "" {
			return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("missing authentication credentials"))
		}

		// Validate token
		claims, err := i.jwtManager.ValidateToken(tokenString, TokenTypeAccess)
		if err != nil {
			return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("invalid or expired token"))
		}

		// Add user context
		userCtx := &UserContext{
			ID:    claims.UserID,
			Email: claims.Email,
			Role:  claims.Role,
		}
		ctx = WithUser(ctx, userCtx)

		return next(ctx, req)
	}
}

// WrapStreamingClient implements connect.Interceptor.
func (i *AuthInterceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return next
}

// WrapStreamingHandler implements connect.Interceptor.
func (i *AuthInterceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return next
}

// AuthzInterceptor provides Connect-RPC authorization interceptor.
type AuthzInterceptor struct {
	authorizer *Authorizer
}

// NewAuthzInterceptor creates a new authorization interceptor.
func NewAuthzInterceptor(authorizer *Authorizer) *AuthzInterceptor {
	return &AuthzInterceptor{authorizer: authorizer}
}

// WrapUnary implements connect.Interceptor.
func (i *AuthzInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		procedure := req.Spec().Procedure

		// Skip authz for public procedures
		if PublicProcedures[procedure] {
			return next(ctx, req)
		}

		subjectID, role, ok := SubjectFromContext(ctx)
		if !ok {
			return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
		}

		// Extract action name from procedure (e.g., "/pm.v1.ControlService/GetUser" -> "GetUser")
		parts := strings.Split(procedure, "/")
		action := parts[len(parts)-1]

		// Build authorization input
		input := AuthzInput{
			Role:      role,
			SubjectID: subjectID,
			Action:    action,
		}

		// Check authorization
		allowed, err := i.authorizer.Authorize(ctx, input)
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, errors.New("authorization check failed"))
		}
		if !allowed {
			return nil, connect.NewError(connect.CodePermissionDenied, errors.New("permission denied"))
		}

		return next(ctx, req)
	}
}

// WrapStreamingClient implements connect.Interceptor.
func (i *AuthzInterceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return next
}

// WrapStreamingHandler implements connect.Interceptor.
func (i *AuthzInterceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return next
}

// ============================================================================
// SESSION CONTEXT INTERCEPTOR (for PostgreSQL RLS)
// ============================================================================

// SessionInterceptor acquires a dedicated database connection, sets the
// PostgreSQL session context for RLS policies, and stashes RLS-scoped
// queries in the Go context so handlers use the same connection.
type SessionInterceptor struct {
	store *store.Store
}

// NewSessionInterceptor creates a new session context interceptor.
func NewSessionInterceptor(st *store.Store) *SessionInterceptor {
	return &SessionInterceptor{store: st}
}

// WrapUnary implements connect.Interceptor.
func (i *SessionInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		// Determine the session context based on the authenticated subject.
		sc := i.sessionContextFromCtx(ctx)

		// Acquire a dedicated connection and set the session context on it.
		cws, err := i.store.AcquireWithSession(ctx, sc)
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, errors.New("failed to set session context"))
		}
		defer cws.Release()

		// Stash the RLS-scoped queries in the Go context so handlers
		// pick them up via store.QueriesFromContext(ctx).
		ctx = store.ContextWithQueries(ctx, cws.Queries())

		return next(ctx, req)
	}
}

// sessionContextFromCtx builds a SessionContext from the authenticated
// user/device in the Go context.
func (i *SessionInterceptor) sessionContextFromCtx(ctx context.Context) store.SessionContext {
	if userCtx, ok := UserFromContext(ctx); ok {
		switch userCtx.Role {
		case "admin":
			return store.AdminSessionContext(userCtx.ID)
		case "device":
			return store.DeviceSessionContext(userCtx.ID)
		default:
			return store.UserSessionContext(userCtx.ID)
		}
	}
	if deviceCtx, ok := DeviceFromContext(ctx); ok {
		return store.DeviceSessionContext(deviceCtx.ID)
	}
	return store.SystemSessionContext()
}

// WrapStreamingClient implements connect.Interceptor.
func (i *SessionInterceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return next
}

// WrapStreamingHandler implements connect.Interceptor.
func (i *SessionInterceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return next
}
