package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"connectrpc.com/connect"
	"github.com/golang-jwt/jwt/v5"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1/powermanagev1connect"
	"github.com/manchtools/power-manage/server/internal/middleware"
)

// Error code constants carried in the structured error detail.
const (
	errRateLimited      = "rate_limited"
	errNotAuthenticated = "not_authenticated"
	errTokenExpired     = "token_expired"
	errPermissionDenied = "permission_denied"
)

// ControlProcedurePrefix is the Connect path prefix every control
// procedure shares.
const ControlProcedurePrefix = "/" + powermanagev1connect.ControlServiceName + "/"

// PublicProcedures are the procedures that carry no session token.
//
// Human login is OIDC only, so the public set is the SSO handshake, the
// session lifecycle a client must be able to drive without a valid
// access token, and the two device-certificate procedures whose caller
// authenticates with an enrollment token or its existing certificate.
var PublicProcedures = map[string]bool{
	powermanagev1connect.ControlServiceRefreshTokenProcedure:     true,
	powermanagev1connect.ControlServiceLogoutProcedure:           true,
	powermanagev1connect.ControlServiceRegisterProcedure:         true,
	powermanagev1connect.ControlServiceRenewCertificateProcedure: true,
	powermanagev1connect.ControlServiceListAuthMethodsProcedure:  true,
	powermanagev1connect.ControlServiceGetSSOLoginURLProcedure:   true,
	powermanagev1connect.ControlServiceSSOCallbackProcedure:      true,
}

// procedureAlternatives maps a procedure to the permission keys that
// can authorize it. The authorization interceptor passes the procedure
// when the actor holds ANY of the alternatives; the handler then
// narrows to the specific permission for the request shape.
//
// It exists for procedures whose authorization depends on a runtime
// property of the request — CreateDeviceGroup is satisfied by either
// the static or the dynamic creation permission depending on whether
// the request carries a query. A procedure listed here is gated
// EXCLUSIVELY by its alternatives; the default base-key path is not a
// fallback.
//
// Unexported: an exported mutable map of authorization rules is a
// runtime-tampering surface. Out-of-package callers read
// ProcedureAlternativesSnapshot. The map is written once at package
// init and only read afterwards, so concurrent reads are safe.
var procedureAlternatives = map[string][]string{
	powermanagev1connect.ControlServiceCreateDeviceGroupProcedure: {
		"CreateStaticDeviceGroup",
		"CreateDynamicDeviceGroup",
	},
	powermanagev1connect.ControlServiceCreateUserGroupProcedure: {
		"CreateStaticUserGroup",
		"CreateDynamicUserGroup",
	},
	// The query-update procedures are dynamic-only: a static-group
	// admin cannot satisfy them because only the dynamic permission is
	// listed.
	powermanagev1connect.ControlServiceUpdateDeviceGroupQueryProcedure: {
		"UpdateDynamicDeviceGroupQuery",
	},
	powermanagev1connect.ControlServiceUpdateUserGroupQueryProcedure: {
		"UpdateDynamicUserGroupQuery",
	},
	// The export is a re-serialisation of what the list already
	// returns, so a separate permission could only drift wider or
	// narrower than the data it re-serves.
	powermanagev1connect.ControlServiceExportAuditEventsProcedure: {
		"ListAuditEvents",
	},
}

// ProcedureAlternativesSnapshot returns a deep copy of the
// procedure-alternatives map. The returned value is freshly allocated;
// mutating it does not affect the live authorization policy.
func ProcedureAlternativesSnapshot() map[string][]string {
	out := make(map[string][]string, len(procedureAlternatives))
	for k, v := range procedureAlternatives {
		out[k] = append([]string(nil), v...)
	}
	return out
}

// PermissionIsAlternative reports whether a permission key gates some
// procedure through the alternatives map.
func PermissionIsAlternative(permKey string) bool {
	for _, alts := range procedureAlternatives {
		for _, perm := range alts {
			if perm == permKey {
				return true
			}
		}
	}
	return false
}

// TrustedProxies is the set of addresses trusted to set X-Forwarded-For
// / X-Real-IP. Empty means proxy headers are ignored entirely and the
// direct peer address is always used.
var TrustedProxies []*net.IPNet

// SetTrustedProxies parses CIDR strings and installs them as the
// trusted proxy set. A bare IP is treated as /32 or /128.
func SetTrustedProxies(cidrs []string) {
	var nets []*net.IPNet
	for _, cidr := range cidrs {
		if !strings.Contains(cidr, "/") {
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
		if _, ipNet, err := net.ParseCIDR(cidr); err == nil {
			nets = append(nets, ipNet)
		}
	}
	TrustedProxies = nets
}

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

// resolveClientIP applies trusted-proxy semantics to a direct peer
// address and its forwarded headers.
//
// Proxy headers are honoured only when the direct peer is itself a
// trusted proxy. X-Forwarded-For is walked RIGHT TO LEFT: trusted hops
// are skipped and the first untrusted address is the client, which
// defeats a spoofed leftmost entry. A malformed hop encountered before
// a trustworthy client is established, or an all-trusted chain, falls
// back to the direct peer rather than to a farther-left,
// attacker-controllable value. X-Real-IP is consulted only when
// X-Forwarded-For is absent.
func resolveClientIP(peerIP, xff, xri string) string {
	if !isTrustedProxy(peerIP) {
		return peerIP
	}
	if xff != "" {
		hops := strings.Split(xff, ",")
		for i := len(hops) - 1; i >= 0; i-- {
			hop := strings.TrimSpace(hops[i])
			if net.ParseIP(hop) == nil {
				return peerIP
			}
			if isTrustedProxy(hop) {
				continue
			}
			return hop
		}
		return peerIP
	}
	if xri != "" {
		if ip := strings.TrimSpace(xri); net.ParseIP(ip) != nil {
			return ip
		}
	}
	return peerIP
}

// ClientIPFromHTTP is the http.Request analogue of clientIP, for
// handlers outside the Connect chain (SCIM, health, the OIDC callback).
//
// It returns the empty string when neither the peer address nor the
// proxy headers yield a parsable IP: callers treat that as "could not
// identify" rather than coalescing every anonymous request onto one
// bucket by accident.
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

// clientIP resolves the attributable client address of a Connect
// request. An unparsable peer yields "", which is also the safer
// limiter key: unidentifiable peers share one restrictive bucket
// instead of each getting a fresh one from an attacker-varied string.
func clientIP(req connect.AnyRequest) string {
	peerAddr := req.Peer().Addr
	peerIP := peerAddr
	if host, _, err := net.SplitHostPort(peerAddr); err == nil {
		peerIP = host
	}
	resolved := resolveClientIP(peerIP, req.Header().Get("X-Forwarded-For"), req.Header().Get("X-Real-IP"))
	if net.ParseIP(resolved) != nil {
		return resolved
	}
	return ""
}

// ClientIP is the exported form of clientIP, for handlers that gate
// themselves outside the interceptor chain.
func ClientIP(req connect.AnyRequest) string { return clientIP(req) }

// RateLimiters bundles the per-procedure-family limiters the
// authentication interceptor consults. A nil field disables that gate.
//
// Every limiter is a PROCESS-LOCAL sliding window, which is exactly
// right for the single control instance this design targets: the
// ceiling is the configured ceiling, with no shared store on the
// request path.
type RateLimiters struct {
	// SSOCallback throttles the code-exchange leg of the login flow.
	SSOCallback *RateLimiter
	// Refresh throttles session rotation.
	Refresh *RateLimiter
	// Register and RenewCert throttle the two certificate procedures,
	// each of which runs a CA signing operation and a database write.
	Register  *RateLimiter
	RenewCert *RateLimiter
	// Logout is public, so without a ceiling anyone who learned a
	// refresh token could invalidate that session arbitrarily often.
	Logout *RateLimiter
	// AuthMethods throttles the unauthenticated provider list, which
	// reflects deployment configuration to anonymous callers.
	AuthMethods *RateLimiter
	// SSO throttles GetSSOLoginURL: the most expensive unauthenticated
	// endpoint, since each call writes an auth_state row, decrypts the
	// provider secret and performs outbound OIDC discovery.
	SSO *RateLimiter
	// Authenticated is the general per-user ceiling applied to every
	// authenticated procedure once the token validates. Keyed by the
	// subject id, so two subjects never share a bucket.
	Authenticated *RateLimiter
	// Expensive is a tighter per-user ceiling layered on top for the
	// self-discovered heavy set (see isExpensiveProcedure).
	Expensive *RateLimiter
	// Rejected bounds how fast one source address can produce
	// authentication FAILURES. It gates the rejection-audit write, so
	// a credential-stuffing flood cannot turn the audit log into an
	// amplification target.
	Rejected *RateLimiter
}

// isExpensiveProcedure reports whether an authenticated procedure runs
// a heavy operation — query evaluation, search, an index rebuild, a
// log/osquery fan-out or a bulk export — and warrants a tighter
// per-user ceiling.
//
// Self-discovered from the action name so a newly added Evaluate* /
// Search* / Rebuild* / Query* / *Query / Export* procedure is covered
// automatically rather than from a hand-maintained list that fails
// open. A test walks the real procedure set and asserts the matcher
// recognises at least one, so it can never silently match zero.
func isExpensiveProcedure(action string) bool {
	return strings.HasPrefix(action, "Evaluate") ||
		strings.HasPrefix(action, "Search") ||
		strings.HasPrefix(action, "Rebuild") ||
		strings.HasPrefix(action, "Query") ||
		strings.HasSuffix(action, "Query") ||
		strings.HasPrefix(action, "Export")
}

// IsExpensiveProcedure reports whether an action name matches the
// heavy set. Exported so a guard test can assert the matcher recognises
// at least one real procedure — a self-discovering matcher that matches
// nothing would gate nothing while looking like it did.
func IsExpensiveProcedure(action string) bool { return isExpensiveProcedure(action) }

// ProcedureAction extracts the trailing method name from a Connect
// procedure path.
func ProcedureAction(procedure string) string {
	parts := strings.Split(procedure, "/")
	return parts[len(parts)-1]
}

// RejectionRecorder is the audit seam the authentication interceptor
// uses for the dedicated rejected-authentication operation class. It is
// satisfied by *store.Store; declared as an interface here so the auth
// package does not depend on a concrete store for a single call.
type RejectionRecorder interface {
	RecordRejectedAuthentication(ctx context.Context, att RejectedAuthentication) error
}

// RejectedAuthentication describes one failed authentication attempt.
// Every field is code-derived or a digest: the presented credential
// never appears, only the SHA-256 of it, and the peer address is
// likewise reduced to a digest because it is personal data.
type RejectedAuthentication struct {
	// Procedure is the full Connect method that was attempted.
	Procedure string
	// Reason is a fixed code constant naming why the attempt failed.
	Reason string
	// CredentialFingerprint is the SHA-256 hex digest of the presented
	// bearer value, empty when none was presented.
	CredentialFingerprint string
	// OriginFingerprint is the SHA-256 hex digest of the client
	// address, empty when the peer could not be identified.
	OriginFingerprint string
}

// There is deliberately no claimed-subject field. A rejected attempt
// never authenticated, so it has no actor; recording the id a forged
// token asserted would put an attacker-chosen value in the column that
// means "who did this".

// Fingerprint reduces a value to its SHA-256 hex digest. The empty
// string maps to the empty string rather than to the digest of nothing,
// so "absent" and "present but empty" do not collide.
func Fingerprint(v string) string {
	if v == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:])
}

// AuthInterceptor authenticates Connect requests.
type AuthInterceptor struct {
	logger     *slog.Logger
	jwtManager *JWTManager
	limiters   RateLimiters
	rejections RejectionRecorder
	// bootstrap admits the host-authorized setup principal. Nil when
	// no bootstrap path is wired.
	bootstrap BootstrapAuthenticator
}

// BootstrapAuthenticator consumes a host-authorized bootstrap token and
// returns the reserved principal it admits. Consumption is single-use
// and audited by the implementation.
type BootstrapAuthenticator interface {
	AuthenticateBootstrapToken(ctx context.Context, token string) (*UserContext, error)
}

// NewAuthInterceptor creates the authentication interceptor.
func NewAuthInterceptor(logger *slog.Logger, jwtManager *JWTManager, limiters RateLimiters, rejections RejectionRecorder) *AuthInterceptor {
	return &AuthInterceptor{logger: logger, jwtManager: jwtManager, limiters: limiters, rejections: rejections}
}

// WithBootstrapAuthenticator wires the host-authorized setup path.
func (i *AuthInterceptor) WithBootstrapAuthenticator(b BootstrapAuthenticator) *AuthInterceptor {
	i.bootstrap = b
	return i
}

// BootstrapTokenScheme is the Authorization scheme a host-authorized
// bootstrap token is presented under. It is deliberately NOT "Bearer":
// a bootstrap token must never be accepted anywhere a session token is
// expected, and a distinct scheme makes that a parse-level property
// rather than a validation-order one.
const BootstrapTokenScheme = "PowerManage-Bootstrap"

// WrapUnary implements connect.Interceptor.
func (i *AuthInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		procedure := req.Spec().Procedure

		if err := i.applyPublicLimiters(ctx, procedure, req); err != nil {
			return nil, err
		}

		if PublicProcedures[procedure] {
			return next(ctx, req)
		}

		scheme, credential, err := parseAuthorization(req.Header().Get("Authorization"))
		if err != nil {
			return nil, i.rejectAuthentication(ctx, req, procedure, errNotAuthenticated, "",
				connect.CodeUnauthenticated, err.Error())
		}

		if strings.EqualFold(scheme, BootstrapTokenScheme) {
			return i.authenticateBootstrap(ctx, next, req, procedure, credential)
		}
		if !strings.EqualFold(scheme, "Bearer") {
			return nil, i.rejectAuthentication(ctx, req, procedure, errNotAuthenticated, credential,
				connect.CodeUnauthenticated, "invalid authorization header format")
		}

		claims, err := i.jwtManager.ValidateToken(credential, TokenTypeAccess)
		if err != nil {
			// An expired token is separated from every other failure so
			// the client can distinguish "refresh and retry" from "this
			// value can never become valid, log in again". Signature,
			// algorithm, issuer and token-type failures all collapse
			// into the second case: telling a caller WHICH check their
			// forgery failed is an oracle.
			code, msg := errNotAuthenticated, "invalid token"
			if errors.Is(err, jwt.ErrTokenExpired) {
				code, msg = errTokenExpired, "token expired"
			}
			return nil, i.rejectAuthentication(ctx, req, procedure, code, credential, connect.CodeUnauthenticated, msg)
		}

		if i.limiters.Authenticated != nil && !i.limiters.Authenticated.Allow("uid:"+claims.UserID) {
			i.logger.Warn("rate limit exceeded", "limiter", "authenticated", "procedure", procedure)
			return nil, authErrorCtx(ctx, errRateLimited, connect.CodeResourceExhausted, "too many requests, try again later")
		}
		if i.limiters.Expensive != nil && isExpensiveProcedure(ProcedureAction(procedure)) {
			if !i.limiters.Expensive.Allow("uid:" + claims.UserID) {
				i.logger.Warn("rate limit exceeded", "limiter", "expensive", "procedure", procedure)
				return nil, authErrorCtx(ctx, errRateLimited, connect.CodeResourceExhausted, "too many expensive requests, try again later")
			}
		}

		ctx = WithUser(ctx, &UserContext{
			ID:             claims.UserID,
			Kind:           PrincipalUser,
			Email:          claims.Email,
			Permissions:    claims.Permissions,
			ScopedGrants:   claims.ScopedGrants,
			SessionVersion: claims.SessionVersion,
		})
		return next(ctx, req)
	}
}

// authenticateBootstrap consumes a host-authorized setup token. The
// token is single-use, so a rejection here is terminal for that value.
func (i *AuthInterceptor) authenticateBootstrap(
	ctx context.Context,
	next connect.UnaryFunc,
	req connect.AnyRequest,
	procedure, credential string,
) (connect.AnyResponse, error) {
	if i.bootstrap == nil {
		return nil, i.rejectAuthentication(ctx, req, procedure, errNotAuthenticated, credential,
			connect.CodeUnauthenticated, "invalid token")
	}
	principal, err := i.bootstrap.AuthenticateBootstrapToken(ctx, credential)
	if err != nil {
		return nil, i.rejectAuthentication(ctx, req, procedure, errNotAuthenticated, credential,
			connect.CodeUnauthenticated, "invalid token")
	}
	return next(WithUser(ctx, principal), req)
}

// applyPublicLimiters runs the per-procedure ceilings that gate the
// unauthenticated surface, before any handler work.
func (i *AuthInterceptor) applyPublicLimiters(ctx context.Context, procedure string, req connect.AnyRequest) error {
	type gate struct {
		limiter *RateLimiter
		name    string
		message string
	}
	var g gate
	switch procedure {
	case powermanagev1connect.ControlServiceSSOCallbackProcedure:
		g = gate{i.limiters.SSOCallback, "sso_callback", "too many login attempts, try again later"}
	case powermanagev1connect.ControlServiceRefreshTokenProcedure:
		g = gate{i.limiters.Refresh, "refresh", "too many refresh attempts, try again later"}
	case powermanagev1connect.ControlServiceRegisterProcedure:
		g = gate{i.limiters.Register, "register", "too many registration attempts, try again later"}
	case powermanagev1connect.ControlServiceLogoutProcedure:
		g = gate{i.limiters.Logout, "logout", "too many logout attempts, try again later"}
	case powermanagev1connect.ControlServiceRenewCertificateProcedure:
		g = gate{i.limiters.RenewCert, "renew_cert", "too many certificate renewal attempts, try again later"}
	case powermanagev1connect.ControlServiceListAuthMethodsProcedure:
		g = gate{i.limiters.AuthMethods, "auth_methods", "too many requests, try again later"}
	case powermanagev1connect.ControlServiceGetSSOLoginURLProcedure:
		g = gate{i.limiters.SSO, "sso", "too many requests, try again later"}
	default:
		return nil
	}
	if g.limiter == nil {
		return nil
	}
	if !g.limiter.Allow(clientIP(req)) {
		i.logger.Warn("rate limit exceeded", "limiter", g.name, "procedure", procedure)
		return authErrorCtx(ctx, errRateLimited, connect.CodeResourceExhausted, g.message)
	}
	return nil
}

// rejectAuthentication records the attempt under the dedicated
// rejected-authentication operation class and returns the error the
// caller sees.
//
// The audit write is gated by the Rejected limiter: a flood of bad
// credentials from one source is throttled, so the audit log cannot be
// used as a write amplifier. The rejection itself is unconditional —
// throttling changes what is RECORDED, never what is ADMITTED.
func (i *AuthInterceptor) rejectAuthentication(
	ctx context.Context,
	req connect.AnyRequest,
	procedure, reason, credential string,
	code connect.Code,
	message string,
) error {
	ip := clientIP(req)
	if i.rejections != nil && (i.limiters.Rejected == nil || i.limiters.Rejected.Allow("rej:"+ip)) {
		att := RejectedAuthentication{
			Procedure:             procedure,
			Reason:                reason,
			CredentialFingerprint: Fingerprint(credential),
			OriginFingerprint:     Fingerprint(ip),
		}
		if err := i.rejections.RecordRejectedAuthentication(ctx, att); err != nil {
			i.logger.Error("failed to record rejected authentication",
				"procedure", procedure, "reason", reason, "error", err)
		}
	}
	return authErrorCtx(ctx, reason, code, message)
}

// parseAuthorization splits an Authorization header into its scheme and
// credential. A missing header, a malformed one and an empty credential
// are all reported as the same "no usable credential" condition.
func parseAuthorization(header string) (scheme, credential string, err error) {
	if header == "" {
		return "", "", errors.New("missing authentication credentials")
	}
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 {
		return "", "", errors.New("invalid authorization header format")
	}
	scheme, credential = parts[0], strings.TrimSpace(parts[1])
	if credential == "" {
		return "", "", errors.New("missing authentication credentials")
	}
	return scheme, credential, nil
}

// WrapStreamingClient implements connect.Interceptor.
func (i *AuthInterceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return next
}

// WrapStreamingHandler refuses streaming: the control API is unary
// only, and an unauthenticated streaming path would be a hole around
// the unary gate above.
func (i *AuthInterceptor) WrapStreamingHandler(connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return func(context.Context, connect.StreamingHandlerConn) error {
		return connect.NewError(connect.CodeUnimplemented, errors.New("streaming RPCs are not supported on the control server"))
	}
}

// AuthzInterceptor is the coarse permission gate. It answers "does this
// actor hold anything that could authorize this procedure"; each
// handler still expresses its own resource-specific authorization.
type AuthzInterceptor struct{}

// NewAuthzInterceptor creates the authorization interceptor.
func NewAuthzInterceptor() *AuthzInterceptor { return &AuthzInterceptor{} }

// WrapUnary implements connect.Interceptor.
func (i *AuthzInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		procedure := req.Spec().Procedure
		if PublicProcedures[procedure] {
			return next(ctx, req)
		}

		userCtx, ok := UserFromContext(ctx)
		if !ok {
			return nil, authErrorCtx(ctx, errNotAuthenticated, connect.CodeUnauthenticated, "not authenticated")
		}

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

		if !Authorize(AuthzInput{
			Permissions:  userCtx.Permissions,
			SubjectID:    userCtx.ID,
			SelfEligible: userCtx.CanOwnResources(),
			Action:       ProcedureAction(procedure),
		}) {
			return nil, authErrorCtx(ctx, errPermissionDenied, connect.CodePermissionDenied, "permission denied")
		}
		return next(ctx, req)
	}
}

// WrapStreamingClient implements connect.Interceptor.
func (i *AuthzInterceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return next
}

// WrapStreamingHandler refuses streaming, matching the authentication
// interceptor.
func (i *AuthzInterceptor) WrapStreamingHandler(connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return func(context.Context, connect.StreamingHandlerConn) error {
		return connect.NewError(connect.CodeUnimplemented, errors.New("streaming RPCs are not supported on the control server"))
	}
}

// authErrorCtx builds a connect error carrying the structured detail
// the web client correlates on. The message is a fixed string; no
// request input and no credential material reaches it.
func authErrorCtx(ctx context.Context, code string, connectCode connect.Code, msg string) *connect.Error {
	e := connect.NewError(connectCode, errors.New(msg))
	detail := &pmv1.ErrorDetail{Code: code, RequestId: middleware.RequestIDFromContext(ctx)}
	if d, err := connect.NewErrorDetail(detail); err == nil {
		e.AddDetail(d)
	}
	return e
}
