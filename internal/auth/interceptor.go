package auth

import (
	"context"
	"errors"
	"net"
	"strings"

	"connectrpc.com/connect"
)

// PublicProcedures are procedures that don't require authentication.
var PublicProcedures = map[string]bool{
	"/pm.v1.ControlService/Login":           true,
	"/pm.v1.ControlService/RefreshToken":    true,
	"/pm.v1.ControlService/Logout":          true,
	"/pm.v1.ControlService/Register":        true,
	"/pm.v1.ControlService/VerifyLoginTOTP": true,
	"/pm.v1.ControlService/ListAuthMethods": true,
	"/pm.v1.ControlService/GetSSOLoginURL":  true,
	"/pm.v1.ControlService/SSOCallback":             true,
	"/pm.v1.ControlService/AuthenticateDeviceUser":  true,
	"/pm.v1.ControlService/GetDeviceLoginURL":       true,
	"/pm.v1.ControlService/DeviceLoginCallback":     true,
	"/pm.v1.ControlService/ListDeviceUsers":         true,
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

		// Rate limit login attempts by client IP
		if (procedure == "/pm.v1.ControlService/Login" || procedure == "/pm.v1.ControlService/VerifyLoginTOTP" || procedure == "/pm.v1.ControlService/SSOCallback") && i.loginLimiter != nil {
			ip := clientIP(req)
			if !i.loginLimiter.Allow(ip) {
				return nil, connect.NewError(connect.CodeResourceExhausted, errors.New("too many login attempts, try again later"))
			}
		}

		// Rate limit token refresh attempts by client IP
		if procedure == "/pm.v1.ControlService/RefreshToken" && i.refreshLimiter != nil {
			ip := clientIP(req)
			if !i.refreshLimiter.Allow(ip) {
				return nil, connect.NewError(connect.CodeResourceExhausted, errors.New("too many refresh attempts, try again later"))
			}
		}

		// Rate limit registration attempts by client IP
		if procedure == "/pm.v1.ControlService/Register" && i.registerLimiter != nil {
			ip := clientIP(req)
			if !i.registerLimiter.Allow(ip) {
				return nil, connect.NewError(connect.CodeResourceExhausted, errors.New("too many registration attempts, try again later"))
			}
		}

		// Skip auth for public procedures
		if PublicProcedures[procedure] {
			return next(ctx, req)
		}

		// Extract token from Authorization: Bearer header
		authHeader := req.Header().Get("Authorization")
		if authHeader == "" {
			return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("missing authentication credentials"))
		}
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("invalid authorization header format"))
		}
		tokenString := parts[1]
		if tokenString == "" {
			return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("missing authentication credentials"))
		}

		// Validate token
		claims, err := i.jwtManager.ValidateToken(tokenString, TokenTypeAccess)
		if err != nil {
			return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("invalid or expired token"))
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
func (i *AuthInterceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return next
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
				return nil, connect.NewError(connect.CodePermissionDenied, errors.New("permission denied"))
			}
			return next(ctx, req)
		}

		// User context — permissions already on UserContext from JWT
		userCtx, ok := UserFromContext(ctx)
		if !ok {
			return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
		}

		input := AuthzInput{
			Permissions: userCtx.Permissions,
			SubjectID:   userCtx.ID,
			Action:      action,
		}

		if !Authorize(input) {
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
