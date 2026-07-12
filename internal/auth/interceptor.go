package auth

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"connectrpc.com/connect"
	"github.com/golang-jwt/jwt/v5"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
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
	// Agent-facing CRL fetch (spec 31): served over CA-pinned TLS, no JWT —
	// mirrors RenewCertificate. Rate-limited below.
	"/pm.v1.ControlService/GetCertificateRevocationList": true,
	"/pm.v1.ControlService/VerifyLoginTOTP":              true,
	"/pm.v1.ControlService/ListAuthMethods":              true,
	"/pm.v1.ControlService/GetSSOLoginURL":               true,
	"/pm.v1.ControlService/SSOCallback":                  true,
}

// procedureAlternatives maps a Connect-RPC procedure path to the
// set of permission keys that can authorize it. The AuthzInterceptor
// passes the procedure if the actor holds ANY of the listed
// alternatives — handler-level dispatch then narrows to the specific
// permission based on the request shape.
//
// Used for RPCs whose authorization depends on a runtime property
// of the request (e.g. CreateDeviceGroup is satisfied by either
// CreateStaticDeviceGroup or CreateDynamicDeviceGroup depending on
// whether the request carries a dynamic query). The handler MUST
// re-check the specific permission against the request shape — the
// interceptor only guarantees "actor holds at least one of these".
//
// Lookup precedence inside WrapUnary:
//  1. PublicProcedures (bypass)
//  2. Device context (separate authz path)
//  3. procedureAlternatives (this map) — if a procedure has an
//     entry, ONLY the alternatives are checked. The default
//     base-key Authorize path is NOT a fallback.
//  4. Default: Authorize with action derived from procedure name.
//
// Unexported by design: an exported mutable map of authorization
// rules is a runtime-tampering surface. Out-of-package callers use
// ProcedureAlternativesSnapshot for read-only access. Concurrent
// reads inside WrapUnary are safe because the map is set once at
// package init and never mutated. server #7 T-S2.
var procedureAlternatives = map[string][]string{
	// CreateDeviceGroup splits authorization on req.IsDynamic.
	"/pm.v1.ControlService/CreateDeviceGroup": {
		"CreateStaticDeviceGroup",
		"CreateDynamicDeviceGroup",
	},
	"/pm.v1.ControlService/CreateUserGroup": {
		"CreateStaticUserGroup",
		"CreateDynamicUserGroup",
	},
	// UpdateDeviceGroupQuery is dynamic-only. The legacy permission
	// name was renamed to UpdateDynamicDeviceGroupQuery; the RPC
	// name stays for backward compat. Static-only admins cannot
	// satisfy this procedure because only the dynamic-update perm
	// is listed.
	"/pm.v1.ControlService/UpdateDeviceGroupQuery": {
		"UpdateDynamicDeviceGroupQuery",
	},
	"/pm.v1.ControlService/UpdateUserGroupQuery": {
		"UpdateDynamicUserGroupQuery",
	},
	// ExportAuditEvents is gated by the SAME permission as the list
	// (spec 26): the export is a formatting of what ListAuditEvents
	// already returns, so a separate permission could only drift wider
	// or narrower than the data it re-serves. No handler-level
	// narrowing needed — the alternative IS the exact gate.
	"/pm.v1.ControlService/ExportAuditEvents": {
		"ListAuditEvents",
	},
}

// ProcedureAlternativesSnapshot returns a deep copy of the
// procedure-alternatives map for read-only inspection by tests and
// out-of-package callers. The returned value is freshly allocated;
// mutating it does NOT affect the live authorization policy.
func ProcedureAlternativesSnapshot() map[string][]string {
	out := make(map[string][]string, len(procedureAlternatives))
	for k, v := range procedureAlternatives {
		out[k] = append([]string(nil), v...)
	}
	return out
}

// proceduresAcceptingAlternative builds the inverse of
// procedureAlternatives: a permission key → true map of every
// permission that appears as an alternative for SOME procedure.
// Used by the parity tests to recognize split / renamed permissions
// (CreateStaticDeviceGroup etc.) as RPC-backed via the alternatives
// map even though no RPC has that literal name.
func proceduresAcceptingAlternative() map[string]bool {
	out := make(map[string]bool)
	for _, alts := range procedureAlternatives {
		for _, perm := range alts {
			out[perm] = true
		}
	}
	return out
}

// PermissionIsAlternative returns true if the given permission key
// appears in procedureAlternatives as a satisfying alternative for
// some procedure. Exported for parity-test consumption.
func PermissionIsAlternative(permKey string) bool {
	return proceduresAcceptingAlternative()[permKey]
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

// resolveClientIP applies trusted-proxy semantics to a direct peer address and
// its forwarded headers, returning the attributable client IP. It is the single
// resolver shared by clientIP (Connect interceptor) and ClientIPFromHTTP, so the
// two paths cannot drift.
//
// Proxy headers are honoured only when peerIP is itself a trusted proxy —
// an untrusted direct peer's headers are ignored entirely. X-Forwarded-For is
// walked RIGHT TO LEFT (spec 29): trusted-proxy hops are skipped and the first
// untrusted address is the client. This defeats a spoofed leftmost entry, which
// the previous first-hop selection trusted. A malformed hop encountered before a
// trustworthy client is established, or an all-trusted chain, falls back to the
// direct peer rather than to a farther-left, attacker-controllable value.
// X-Real-IP is consulted only when X-Forwarded-For is absent. Returns peerIP
// (unvalidated) when no forwarded value applies; callers decide how to treat an
// unparsable peer.
func resolveClientIP(peerIP, xff, xri string) string {
	if !isTrustedProxy(peerIP) {
		return peerIP
	}
	if xff != "" {
		hops := strings.Split(xff, ",")
		for i := len(hops) - 1; i >= 0; i-- {
			hop := strings.TrimSpace(hops[i])
			if net.ParseIP(hop) == nil {
				// Malformed hop: the chain is untrustworthy from here leftward.
				return peerIP
			}
			if isTrustedProxy(hop) {
				continue // a proxy we placed, not the client
			}
			return hop // first untrusted address, walking right to left
		}
		// Every hop was a trusted proxy — the real client is farther upstream
		// than any recorded address; fall back to the direct peer.
		return peerIP
	}
	if xri != "" {
		if ip := strings.TrimSpace(xri); net.ParseIP(ip) != nil {
			return ip
		}
	}
	return peerIP
}

// ClientIPFromHTTP is the http.Request analogue of clientIP — used by
// non-Connect handlers (SCIM, /health, OIDC callback) that need the
// same trusted-proxy semantics. Falls back to RemoteAddr when proxy
// headers are absent or the peer isn't in the trusted-proxy CIDR set.
//
// Returns the empty string if neither RemoteAddr nor proxy headers
// yield a parsable IP — callers should treat that as "could not
// identify" and skip per-IP rate-limit bookkeeping rather than coalesce
// every anonymous request onto a single bucket.
func ClientIPFromHTTP(r *http.Request) string {
	peerIP := r.RemoteAddr
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		peerIP = host
	}
	resolved := resolveClientIP(peerIP, r.Header.Get("X-Forwarded-For"), r.Header.Get("X-Real-IP"))
	if net.ParseIP(resolved) != nil {
		return resolved
	}
	return ""
}

// clientIP extracts the real client IP. Proxy headers (X-Forwarded-For,
// X-Real-IP) are only trusted when the direct peer is in TrustedProxies.
// Falls back to the direct peer address.
func clientIP(req connect.AnyRequest) string {
	peerAddr := req.Peer().Addr
	peerIP := peerAddr
	if host, _, err := net.SplitHostPort(peerAddr); err == nil {
		peerIP = host
	}
	// Validate the resolved value exactly as ClientIPFromHTTP does, so the two
	// paths cannot drift: a peer that isn't a parsable IP (non-TCP transport,
	// unix socket) yields "" rather than a raw non-IP string. "" is also the
	// safer limiter key — unidentifiable peers share one restrictive bucket
	// instead of each getting a fresh one from an attacker-varied string.
	resolved := resolveClientIP(peerIP, req.Header().Get("X-Forwarded-For"), req.Header().Get("X-Real-IP"))
	if net.ParseIP(resolved) != nil {
		return resolved
	}
	return ""
}

// ClientIP is the exported form of clientIP, for handlers that self-gate rate
// limiting outside the interceptor chain (GatewayAuthService, mounted without
// the AuthInterceptor). It applies the same trusted-proxy resolution so the
// limiter key matches what the interceptor would compute.
func ClientIP(req connect.AnyRequest) string { return clientIP(req) }

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
//   - GetCertificateRevocationList          → GetCRL
//   - ListAuthMethods                       → AuthMethods
type RateLimiters struct {
	Login     *RateLimiter
	Refresh   *RateLimiter
	Register  *RateLimiter
	Logout    *RateLimiter
	RenewCert *RateLimiter
	// GetCRL throttles the unauthenticated agent-facing CRL fetch (spec 31):
	// each call does a Valkey ZRANGEBYSCORE, so an unthrottled flood is a
	// resource-amplification vector. Keyed by client IP.
	GetCRL *RateLimiter
	// AuthMethods throttles the unauthenticated ListAuthMethods lookup, which
	// reflects whether an email exists and its auth config — an enumeration
	// oracle if left unthrottled (audit). Keyed by client IP.
	AuthMethods *RateLimiter
	// SSO throttles the unauthenticated GetSSOLoginURL — the most expensive public
	// endpoint: each call writes an auth_state row, AES-GCM-decrypts the provider
	// secret, and performs an outbound OIDC discovery request (spec 29 S3). Left
	// unthrottled it is a storage + outbound-amplification DoS. Keyed by client IP.
	SSO *RateLimiter
	// Authenticated is the general per-user ceiling applied to EVERY
	// authenticated control RPC after the token validates (WS11 #6). It bounds
	// a compromised token or a runaway client from hammering the API. Keyed by
	// the authenticated user ID, so two users never share a bucket.
	Authenticated *RateLimiter
	// Expensive is a tighter per-user ceiling applied ON TOP of Authenticated
	// to the self-discovered set of heavy procedures (query evaluation, search,
	// projector rebuild, log/osquery fan-out — see isExpensiveProcedure). Keyed
	// by the authenticated user ID.
	Expensive *RateLimiter
}

// isExpensiveProcedure reports whether an authenticated control procedure runs
// a heavy operation — dynamic-group query evaluation, search, a projector
// rebuild, a log/osquery fan-out, or a bulk export — that warrants a tighter
// per-user ceiling than ordinary reads. It is self-discovered from the action
// name so a newly added Evaluate* / Search* / Rebuild* / Query* / *Query /
// Export* RPC is covered automatically rather than from a hand-maintained list
// that fails open. A test (TestIsExpensiveProcedure_MatchesRealProcedures)
// walks the ControlService descriptor and asserts the matcher recognises at
// least one real procedure, so it can never silently match zero.
func isExpensiveProcedure(action string) bool {
	return strings.HasPrefix(action, "Evaluate") ||
		strings.HasPrefix(action, "Search") ||
		strings.HasPrefix(action, "Rebuild") ||
		strings.HasPrefix(action, "Query") ||
		strings.HasSuffix(action, "Query") ||
		strings.HasPrefix(action, "Export")
}

// procedureAction extracts the trailing method name from a Connect procedure
// path ("/pm.v1.ControlService/EvaluateDynamicGroup" -> "EvaluateDynamicGroup").
func procedureAction(procedure string) string {
	parts := strings.Split(procedure, "/")
	return parts[len(parts)-1]
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

		// Rate limit GetCertificateRevocationList — public, agent-facing (spec
		// 31). Each call hits Valkey; a legitimate agent fetches at most a few
		// times an hour, so the ceiling is low.
		if procedure == "/pm.v1.ControlService/GetCertificateRevocationList" && i.limiters.GetCRL != nil {
			ip := clientIP(req)
			if !i.limiters.GetCRL.Allow(ip) {
				i.logger.Warn("rate limit exceeded", "limiter", "get_crl", "ip", ip, "procedure", procedure)
				return nil, authErrorCtx(ctx, errRateLimited, connect.CodeResourceExhausted, "too many requests, try again later")
			}
		}

		// Rate limit ListAuthMethods — public, unauthenticated procedure. It
		// reflects whether an email exists and its auth config (password / TOTP /
		// linked providers) to drive the login UI, which makes it an enumeration
		// oracle. Throttling by IP bounds bulk enumeration without removing the
		// legitimate single-email lookup the login page needs (audit).
		if procedure == "/pm.v1.ControlService/ListAuthMethods" && i.limiters.AuthMethods != nil {
			ip := clientIP(req)
			if !i.limiters.AuthMethods.Allow(ip) {
				i.logger.Warn("rate limit exceeded", "limiter", "auth_methods", "ip", ip, "procedure", procedure)
				return nil, authErrorCtx(ctx, errRateLimited, connect.CodeResourceExhausted, "too many requests, try again later")
			}
		}

		// GetSSOLoginURL (public, spec 29 S3) — the most expensive unauthenticated
		// endpoint (auth_state DB write + secret decrypt + outbound OIDC discovery).
		if procedure == "/pm.v1.ControlService/GetSSOLoginURL" && i.limiters.SSO != nil {
			ip := clientIP(req)
			if !i.limiters.SSO.Allow(ip) {
				i.logger.Warn("rate limit exceeded", "limiter", "sso", "ip", ip, "procedure", procedure)
				return nil, authErrorCtx(ctx, errRateLimited, connect.CodeResourceExhausted, "too many requests, try again later")
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

		// Authenticated-RPC rate limiting (WS11 #6). The caller is now
		// authenticated, so key per-user: a stolen token or a misbehaving
		// client cannot exhaust the API, and two users never share a bucket.
		// The general ceiling counts every authenticated call; the tighter
		// "expensive" ceiling additionally gates the self-discovered heavy set.
		// Both run BEFORE next so the limiter gates ahead of any handler work.
		if i.limiters.Authenticated != nil {
			if !i.limiters.Authenticated.Allow("uid:" + claims.UserID) {
				i.logger.Warn("rate limit exceeded", "limiter", "authenticated", "user_id", claims.UserID, "procedure", procedure)
				return nil, authErrorCtx(ctx, errRateLimited, connect.CodeResourceExhausted, "too many requests, try again later")
			}
		}
		if i.limiters.Expensive != nil && isExpensiveProcedure(procedureAction(procedure)) {
			if !i.limiters.Expensive.Allow("uid:" + claims.UserID) {
				i.logger.Warn("rate limit exceeded", "limiter", "expensive", "user_id", claims.UserID, "procedure", procedure)
				return nil, authErrorCtx(ctx, errRateLimited, connect.CodeResourceExhausted, "too many expensive requests, try again later")
			}
		}

		// Add user context with permissions + scoped grants from JWT
		userCtx := &UserContext{
			ID:             claims.UserID,
			Email:          claims.Email,
			Permissions:    claims.Permissions,
			ScopedGrants:   claims.ScopedGrants,
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

		// User context — permissions already on UserContext from JWT
		userCtx, ok := UserFromContext(ctx)
		if !ok {
			return nil, authErrorCtx(ctx, errNotAuthenticated, connect.CodeUnauthenticated, "not authenticated")
		}

		// Procedures whose authorization depends on the request
		// shape (e.g. CreateDeviceGroup → static vs dynamic) consult
		// the procedureAlternatives map: ANY of the listed perms
		// admits the caller. The handler then narrows to the
		// specific permission against the request shape. The
		// default Authorize path is NOT a fallback here — a
		// procedure in the alternatives map is exclusively gated by
		// that list. server #7 T-S2.
		if alts, hasAlt := procedureAlternatives[procedure]; hasAlt {
			for _, alt := range alts {
				for _, perm := range userCtx.Permissions {
					if perm == alt {
						return next(ctx, req)
					}
				}
			}
			return nil, authErrorCtx(ctx, errPermissionDenied, connect.CodePermissionDenied, "permission denied")
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
