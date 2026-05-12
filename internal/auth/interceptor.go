package auth

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"strings"

	"connectrpc.com/connect"
	"github.com/golang-jwt/jwt/v5"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/middleware"
)

// Error code constants for structured error details.
const (
	errRateLimited      = "rate_limited"
	errNotAuthenticated = "not_authenticated"
	errTokenExpired     = "token_expired"
	errPermissionDenied = "permission_denied"
)

// PublicProcedures are procedures that don't require authentication.
var PublicProcedures = map[string]bool{
	"/pm.v1.ControlService/Login":            true,
	"/pm.v1.ControlService/RefreshToken":     true,
	"/pm.v1.ControlService/Logout":           true,
	"/pm.v1.ControlService/Register":         true,
	"/pm.v1.ControlService/RenewCertificate": true,
	"/pm.v1.ControlService/VerifyLoginTOTP":  true,
	"/pm.v1.ControlService/ListAuthMethods":  true,
	"/pm.v1.ControlService/GetSSOLoginURL":   true,
	"/pm.v1.ControlService/SSOCallback":      true,
}

// TrustedProxies is the set of IP addresses/CIDRs trusted to set
// X-Forwarded-For / X-Real-IP headers. If empty, proxy headers are ignored
// and the direct peer address is always used.
var TrustedProxies []*net.IPNet

// SetTrustedProxies parses a list of CIDR strings (e.g. "10.0.0.0/8",
// "172.16.0.0/12") and sets them as trusted proxy sources. Plain IPs
// like "127.0.0.1" are treated as /32 (IPv4) or /128 (IPv6).
func SetTrustedProxies(cidrs []string) {
	var nets []*net.IPNet
	for _, cidr := range cidrs {
		if !strings.Contains(cidr, "/") {
			// Bare IP — convert to /32 or /128
			ip := net.ParseIP(cidr)
			if ip == nil {
				continue
			}
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			continue
		}
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil {
			nets = append(nets, ipNet)
		}
	}
	TrustedProxies = nets
}

// isTrustedProxy checks if an IP is in the trusted proxy list.
func isTrustedProxy(addr string) bool {
	if len(TrustedProxies) == 0 {
		return false
	}
	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}
	for _, n := range TrustedProxies {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// clientIP extracts the real client IP. Proxy headers (X-Forwarded-For,
// X-Real-IP) are only trusted when the direct peer is in TrustedProxies.
// Falls back to the direct peer address.
func clientIP(req connect.AnyRequest) string {
	// Get the direct peer address first
	peerAddr := req.Peer().Addr
	peerIP := peerAddr
	if host, _, err := net.SplitHostPort(peerAddr); err == nil {
		peerIP = host
	}

	// Only trust proxy headers if the direct peer is a trusted proxy
	if isTrustedProxy(peerIP) {
		if xff := req.Header().Get("X-Forwarded-For"); xff != "" {
			ip := strings.TrimSpace(strings.SplitN(xff, ",", 2)[0])
			if parsed := net.ParseIP(ip); parsed != nil {
				return ip
			}
		}
		if xri := req.Header().Get("X-Real-IP"); xri != "" {
			ip := strings.TrimSpace(xri)
			if parsed := net.ParseIP(ip); parsed != nil {
				return ip
			}
		}
	}

	return peerIP
}

// RateLimiters bundles the per-procedure-family rate limiters the
// AuthInterceptor consults. nil fields disable the corresponding gate.
// The split lets each family carry a different ceiling: Login is a
// credential-spray vector and gets the tightest budget; RefreshToken
// has the loosest because legitimate clients refresh frequently.
//
// Procedure → field mapping (see WrapUnary):
//   - Login / VerifyLoginTOTP / SSOCallback → Login
//   - RefreshToken                          → Refresh
//   - Register                              → Register
//   - Logout                                → Logout
//   - RenewCertificate                      → RenewCert
type RateLimiters struct {
	Login     *RateLimiter
	Refresh   *RateLimiter
	Register  *RateLimiter
	Logout    *RateLimiter
	RenewCert *RateLimiter
}

// AuthInterceptor provides Connect-RPC authentication interceptor.
type AuthInterceptor struct {
	logger     *slog.Logger
	jwtManager *JWTManager
	limiters   RateLimiters
}

// NewAuthInterceptor creates a new authentication interceptor.
func NewAuthInterceptor(logger *slog.Logger, jwtManager *JWTManager, limiters RateLimiters) *AuthInterceptor {
	return &AuthInterceptor{logger: logger, jwtManager: jwtManager, limiters: limiters}
}

// WrapUnary implements connect.Interceptor.
func (i *AuthInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		procedure := req.Spec().Procedure

		// Rate limit login attempts by client IP. Login + VerifyLoginTOTP +
		// SSOCallback share one budget — they're all credential-spray
		// vectors that a defender treats as one logical "auth attempt"
		// regardless of which RPC the attacker pokes.
		if (procedure == "/pm.v1.ControlService/Login" || procedure == "/pm.v1.ControlService/VerifyLoginTOTP" || procedure == "/pm.v1.ControlService/SSOCallback") && i.limiters.Login != nil {
			ip := clientIP(req)
			if !i.limiters.Login.Allow(ip) {
				i.logger.Warn("rate limit exceeded", "limiter", "login", "ip", ip, "procedure", procedure)
				return nil, authErrorCtx(ctx, errRateLimited, connect.CodeResourceExhausted, "too many login attempts, try again later")
			}
		}

		// Rate limit token refresh attempts by client IP
		if procedure == "/pm.v1.ControlService/RefreshToken" && i.limiters.Refresh != nil {
			ip := clientIP(req)
			if !i.limiters.Refresh.Allow(ip) {
				i.logger.Warn("rate limit exceeded", "limiter", "refresh", "ip", ip, "procedure", procedure)
				return nil, authErrorCtx(ctx, errRateLimited, connect.CodeResourceExhausted, "too many refresh attempts, try again later")
			}
		}

		// Rate limit registration attempts by client IP
		if procedure == "/pm.v1.ControlService/Register" && i.limiters.Register != nil {
			ip := clientIP(req)
			if !i.limiters.Register.Allow(ip) {
				i.logger.Warn("rate limit exceeded", "limiter", "register", "ip", ip, "procedure", procedure)
				return nil, authErrorCtx(ctx, errRateLimited, connect.CodeResourceExhausted, "too many registration attempts, try again later")
			}
		}

		// Rate limit Logout — public procedure (#142). Without a limiter,
		// an attacker who learned a session token (XSS, log leak, shared
		// browser) could invalidate that user's sessions arbitrarily often:
		// each call is a single DB write with no backoff.
		if procedure == "/pm.v1.ControlService/Logout" && i.limiters.Logout != nil {
			ip := clientIP(req)
			if !i.limiters.Logout.Allow(ip) {
				i.logger.Warn("rate limit exceeded", "limiter", "logout", "ip", ip, "procedure", procedure)
				return nil, authErrorCtx(ctx, errRateLimited, connect.CodeResourceExhausted, "too many logout attempts, try again later")
			}
		}

		// Rate limit RenewCertificate — public procedure (#142). Each
		// call exercises the CA signing path + a DB write; concurrent
		// floods could exhaust signer throughput. Cert rotation happens
		// once per cert-lifetime so the legitimate ceiling is very low.
		if procedure == "/pm.v1.ControlService/RenewCertificate" && i.limiters.RenewCert != nil {
			ip := clientIP(req)
			if !i.limiters.RenewCert.Allow(ip) {
				i.logger.Warn("rate limit exceeded", "limiter", "renew_cert", "ip", ip, "procedure", procedure)
				return nil, authErrorCtx(ctx, errRateLimited, connect.CodeResourceExhausted, "too many certificate renewal attempts, try again later")
			}
		}

		// Skip auth for public procedures
		if PublicProcedures[procedure] {
			return next(ctx, req)
		}

		// Extract token from Authorization: Bearer header
		authHeader := req.Header().Get("Authorization")
		if authHeader == "" {
			return nil, authErrorCtx(ctx, errNotAuthenticated, connect.CodeUnauthenticated, "missing authentication credentials")
		}
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			return nil, authErrorCtx(ctx, errNotAuthenticated, connect.CodeUnauthenticated, "invalid authorization header format")
		}
		tokenString := parts[1]
		if tokenString == "" {
			return nil, authErrorCtx(ctx, errNotAuthenticated, connect.CodeUnauthenticated, "missing authentication credentials")
		}

		// Validate token. Distinguish "expired" from "malformed /
		// signature-invalid / wrong-type" so the web client can show
		// the right UX (silent refresh vs forced re-login). Falls back
		// to errNotAuthenticated for non-expiry failures so the web
		// error mapping doesn't trigger refresh-and-retry on a token
		// that can never become valid (#139, audit Bundle A).
		claims, err := i.jwtManager.ValidateToken(tokenString, TokenTypeAccess)
		if err != nil {
			if errors.Is(err, jwt.ErrTokenExpired) {
				return nil, authErrorCtx(ctx, errTokenExpired, connect.CodeUnauthenticated, "token expired")
			}
			return nil, authErrorCtx(ctx, errNotAuthenticated, connect.CodeUnauthenticated, "invalid token")
		}

		// Add user context with permissions from JWT
		userCtx := &UserContext{
			ID:             claims.UserID,
			Email:          claims.Email,
			Permissions:    claims.Permissions,
			SessionVersion: claims.SessionVersion,
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
// Rejects streaming RPCs with Unauthenticated — the control server does not use streaming RPCs.
// If streaming is ever needed, this must be updated with proper auth logic.
func (i *AuthInterceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		return connect.NewError(connect.CodeUnimplemented, errors.New("streaming RPCs are not supported on the control server"))
	}
}

// AuthzInterceptor provides Connect-RPC authorization interceptor.
// It uses the Go Authorize function with permissions already on the UserContext (from JWT).
type AuthzInterceptor struct{}

// NewAuthzInterceptor creates a new authorization interceptor.
func NewAuthzInterceptor() *AuthzInterceptor {
	return &AuthzInterceptor{}
}

// WrapUnary implements connect.Interceptor.
func (i *AuthzInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		procedure := req.Spec().Procedure

		// Skip authz for public procedures
		if PublicProcedures[procedure] {
			return next(ctx, req)
		}

		// Extract action name from procedure (e.g., "/pm.v1.ControlService/GetUser" -> "GetUser")
		parts := strings.Split(procedure, "/")
		action := parts[len(parts)-1]

		// Check if device context
		if deviceCtx, ok := DeviceFromContext(ctx); ok {
			input := AuthzInput{
				IsDevice:  true,
				SubjectID: deviceCtx.ID,
				Action:    action,
			}
			if !Authorize(input) {
				return nil, authErrorCtx(ctx, errPermissionDenied, connect.CodePermissionDenied, "permission denied")
			}
			return next(ctx, req)
		}

		// User context — permissions already on UserContext from JWT
		userCtx, ok := UserFromContext(ctx)
		if !ok {
			return nil, authErrorCtx(ctx, errNotAuthenticated, connect.CodeUnauthenticated, "not authenticated")
		}

		input := AuthzInput{
			Permissions: userCtx.Permissions,
			SubjectID:   userCtx.ID,
			Action:      action,
		}

		if !Authorize(input) {
			return nil, authErrorCtx(ctx, errPermissionDenied, connect.CodePermissionDenied, "permission denied")
		}

		return next(ctx, req)
	}
}

// WrapStreamingClient implements connect.Interceptor.
func (i *AuthzInterceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return next
}

// WrapStreamingHandler implements connect.Interceptor.
// Rejects streaming RPCs — the control server does not use streaming RPCs.
func (i *AuthzInterceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		return connect.NewError(connect.CodeUnimplemented, errors.New("streaming RPCs are not supported on the control server"))
	}
}

// authErrorCtx creates a connect.Error with a structured ErrorDetail containing the error code
// and the request ID from context for client-side correlation.
func authErrorCtx(ctx context.Context, code string, connectCode connect.Code, msg string) *connect.Error {
	e := connect.NewError(connectCode, errors.New(msg))
	detail := &pm.ErrorDetail{Code: code, RequestId: middleware.RequestIDFromContext(ctx)}
	if d, err := connect.NewErrorDetail(detail); err == nil {
		e.AddDetail(d)
	}
	return e
}
