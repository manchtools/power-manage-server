package api

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"regexp"
	"time"

	"connectrpc.com/connect"
	"github.com/oklog/ulid/v2"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage-sdk/gen/go/pm/v1/pmv1connect"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/ca"
	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/eventtypes/payloads"
	"github.com/manchtools/power-manage/server/internal/store"
)

// GatewayAuthHandler implements the public, token-gated GatewayAuthService
// (spec 31). A gateway self-enrolls on boot by submitting a CSR with the shared
// bootstrap token; control issues a per-gateway cert whose CN is a fresh ULID
// gateway_id. It mirrors RegistrationHandler.Register for agents.
//
// It is mounted WITHOUT the auth/authz interceptors (like InternalService), so
// it self-gates: constant-time token compare + per-IP rate limiting in the
// handler. That keeps a foreign-service procedure out of ControlService's
// PublicProcedures allow-list.
type GatewayAuthHandler struct {
	store       *store.Store
	ca          *ca.CA
	enrollToken string
	// gatewayHost is this deployment's authoritative gateway host, derived once
	// from CONTROL_GATEWAY_URL. It is the sole source of the DNS SAN stamped on
	// every enrolled gateway cert (spec 31 D1) — the enrollee's claimed hostname
	// is only cross-checked against it, never trusted for issuance.
	gatewayHost string
	limiter     *auth.RateLimiter
	logger      *slog.Logger
	// clientIP resolves the trusted client IP (trusted-proxy aware). Seam for
	// tests; defaults to auth.ClientIP.
	clientIP func(connect.AnyRequest) string
	now      func() time.Time
}

// rfc1123Host matches a canonical DNS name: dot-separated alphanumeric labels
// with interior hyphens, no wildcard, no underscore, no trailing dot. The same
// shape the proto tag (hostname_rfc1123) enforces on the enrollee's claim — a
// derived host outside it could never be matched by a valid claim anyway, but
// catching it at boot beats every enrollment failing at runtime.
var rfc1123Host = regexp.MustCompile(`^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9])(\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]))*$`)

// gatewayHostFromURL extracts the DNS host from CONTROL_GATEWAY_URL. It rejects
// an empty host, an IP literal, and any non-canonical DNS name (wildcards,
// underscores, trailing dots): the gateway cert carries a DNS SAN (agents
// verify a DNS name at the mTLS handshake), and a SAN outside the canonical
// shape either cannot back the mTLS identity (IP-in-DNS-SAN is never matched
// as an IP) or would broaden it (a wildcard SAN signed by the fleet CA).
func gatewayHostFromURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("parse gateway URL: %w", err)
	}
	host := u.Hostname()
	if host == "" {
		return "", fmt.Errorf("gateway URL %q has no host", RedactGatewayURL(raw))
	}
	if net.ParseIP(host) != nil {
		return "", fmt.Errorf("gateway URL host %q is an IP literal; a DNS name is required (the gateway cert's DNS SAN cannot be an IP)", host)
	}
	if len(host) > 253 || !rfc1123Host.MatchString(host) {
		return "", fmt.Errorf("gateway URL host %q is not a canonical DNS name (no wildcards, underscores, or trailing dots)", host)
	}
	return host, nil
}

// NewGatewayAuthHandler creates the enrollment handler. enrollToken is the
// shared bootstrap secret (CONTROL_GATEWAY_ENROLL_TOKEN); an empty token means
// enrollment is effectively disabled (every attempt is rejected). gatewayURL is
// CONTROL_GATEWAY_URL — the authoritative public gateway address; its host
// becomes the DNS SAN of every issued gateway cert. Panics when gatewayURL has
// no canonical DNS host (empty, an IP literal, a wildcard, an underscore, or a
// trailing dot), matching NewRegistrationHandler's
// fail-fast: main.go validates CONTROL_GATEWAY_URL at boot, so reaching the
// constructor with an unusable value is a configuration error that must surface
// at startup, not silently issue certs agents cannot verify.
func NewGatewayAuthHandler(st *store.Store, certAuth *ca.CA, enrollToken, gatewayURL string, limiter *auth.RateLimiter, logger *slog.Logger) *GatewayAuthHandler {
	host, err := gatewayHostFromURL(gatewayURL)
	if err != nil {
		panic(fmt.Sprintf("NewGatewayAuthHandler: %v", err))
	}
	return &GatewayAuthHandler{
		store:       st,
		ca:          certAuth,
		enrollToken: enrollToken,
		gatewayHost: host,
		limiter:     limiter,
		logger:      logger,
		clientIP:    auth.ClientIP,
		now:         time.Now,
	}
}

var _ pmv1connect.GatewayAuthServiceHandler = (*GatewayAuthHandler)(nil)

// EnrollGateway validates the bootstrap token, assigns a ULID gateway_id, signs
// the CSR into a gateway-class cert with CN = gateway_id, and returns the CA +
// cert. The response carries no gateway_id field — the id is the cert CN.
func (h *GatewayAuthHandler) EnrollGateway(ctx context.Context, req *connect.Request[pm.EnrollGatewayRequest]) (*connect.Response[pm.EnrollGatewayResponse], error) {
	// Rate limit first (AC4) — this handler is outside the AuthInterceptor, so
	// the limiter that protects Register/RenewCert is applied here by hand. Bound
	// enrollment probing against the shared bootstrap token to 5/min/IP.
	ip := h.clientIP(req)
	if h.limiter != nil && !h.limiter.Allow(ip) {
		h.logger.Warn("gateway enrollment rate limit exceeded", "ip", ip)
		return nil, apiErrorCtx(ctx, ErrRateLimited, connect.CodeResourceExhausted, "too many enrollment attempts")
	}

	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	// Constant-time token check over fixed-length SHA-256 digests, so neither the
	// compare time nor a length difference leaks the token (AC1). An empty
	// configured token rejects every attempt.
	gotHash := sha256.Sum256([]byte(req.Msg.Token))
	wantHash := sha256.Sum256([]byte(h.enrollToken))
	if h.enrollToken == "" || subtle.ConstantTimeCompare(gotHash[:], wantHash[:]) != 1 {
		// Observability backstop (AC3): record the requester IP and the
		// self-reported hostname — never the token nor any digest of it — so
		// repeated probing against the shared bootstrap token is alertable. The IP
		// and attempt rate are what an operator alerts on; a token-hash prefix
		// (D3) only leaked a distinguisher of the attacker's own guesses. No
		// gateway_id is allocated and no event is emitted on this path.
		h.logger.Warn("gateway enrollment rejected: invalid token",
			"ip", ip,
			"hostname", req.Msg.Hostname,
		)
		return nil, apiErrorCtx(ctx, ErrPermissionDenied, connect.CodePermissionDenied, "invalid enrollment token")
	}

	// D1: the DNS SAN stamped on the gateway cert is what agents verify at the
	// mTLS handshake, so it MUST be control-authoritative — never the enrollee's
	// claim. Cross-check the declared hostname (exact match, so an IP literal,
	// mixed case, a trailing dot, or any unlisted name is refused) against this
	// deployment's authoritative gateway host. We then stamp h.gatewayHost — not
	// the claim — below, so even a matching claim can never smuggle a different
	// SAN. Placed after the token check so an unauthenticated probe cannot learn
	// the expected host, and returns InvalidArgument (a client-correctable input
	// error, distinct from the PermissionDenied token failure).
	if req.Msg.Hostname != h.gatewayHost {
		h.logger.Warn("gateway enrollment rejected: hostname does not match the authoritative gateway host",
			"ip", ip, "claimed_hostname", req.Msg.Hostname, "expected_hostname", h.gatewayHost)
		return nil, apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "hostname does not match this deployment's gateway host")
	}

	gatewayID := ulid.Make().String()

	// Sign the CSR into a gateway-class cert. The CA stamps CN = gateway_id, the
	// gateway peer class, and h.gatewayHost as the sole DNS SAN, and rejects any
	// caller-supplied SAN (AC2). Every CSR failure — malformed, forged signature,
	// SAN present — is InvalidArgument.
	cert, err := h.ca.IssueGatewayCertificateFromCSR(gatewayID, req.Msg.Csr, h.gatewayHost)
	if err != nil {
		h.logger.Warn("gateway enrollment: CSR rejected", "ip", ip, "error", err)
		return nil, apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "invalid certificate signing request")
	}

	fingerprint := cert.Fingerprint
	notAfter := cert.NotAfter.Format(time.RFC3339Nano)
	// Record the authoritative host (what the cert actually carries), which the
	// cross-check above already proved equals the claim.
	hostname := h.gatewayHost
	if err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "gateway",
		StreamID:   gatewayID,
		EventType:  string(eventtypes.GatewayEnrolled),
		Data: payloads.GatewayEnrolled{
			Fingerprint: &fingerprint,
			NotAfter:    &notAfter,
			Hostname:    &hostname,
		},
		ActorType: "system",
		ActorID:   "gateway_enrollment",
	}); err != nil {
		h.logger.Error("failed to append GatewayEnrolled event", "gateway_id", gatewayID, "error", err)
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to record enrollment")
	}

	h.logger.Info("gateway enrolled", "gateway_id", gatewayID, "hostname", h.gatewayHost, "not_after", cert.NotAfter)
	return connect.NewResponse(&pm.EnrollGatewayResponse{
		CaCert:      h.ca.CACertPEM(),
		Certificate: cert.CertPEM,
	}), nil
}
