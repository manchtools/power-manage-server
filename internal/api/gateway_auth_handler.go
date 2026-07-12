package api

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"log/slog"
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
	limiter     *auth.RateLimiter
	logger      *slog.Logger
	// clientIP resolves the trusted client IP (trusted-proxy aware). Seam for
	// tests; defaults to auth.ClientIP.
	clientIP func(connect.AnyRequest) string
	now      func() time.Time
}

// NewGatewayAuthHandler creates the enrollment handler. enrollToken is the
// shared bootstrap secret (CONTROL_GATEWAY_ENROLL_TOKEN); an empty token means
// enrollment is effectively disabled (every attempt is rejected).
func NewGatewayAuthHandler(st *store.Store, certAuth *ca.CA, enrollToken string, limiter *auth.RateLimiter, logger *slog.Logger) *GatewayAuthHandler {
	return &GatewayAuthHandler{
		store:       st,
		ca:          certAuth,
		enrollToken: enrollToken,
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
		// Observability backstop (AC3): record the requester IP, the self-reported
		// hostname, and a short token-HASH prefix — never the token itself — so
		// repeated probing against the shared bootstrap token is alertable. No
		// gateway_id is allocated and no event is emitted on this path.
		h.logger.Warn("gateway enrollment rejected: invalid token",
			"ip", ip,
			"hostname", req.Msg.Hostname,
			"token_hash_prefix", hex.EncodeToString(gotHash[:])[:8],
		)
		return nil, apiErrorCtx(ctx, ErrPermissionDenied, connect.CodePermissionDenied, "invalid enrollment token")
	}

	gatewayID := ulid.Make().String()

	// Sign the CSR into a gateway-class cert. The CA stamps CN = gateway_id and
	// the gateway peer class, and rejects any caller-supplied SAN (AC2). Every
	// CSR failure — malformed, forged signature, SAN present — is InvalidArgument.
	cert, err := h.ca.IssueGatewayCertificateFromCSR(gatewayID, req.Msg.Csr)
	if err != nil {
		h.logger.Warn("gateway enrollment: CSR rejected", "ip", ip, "error", err)
		return nil, apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "invalid certificate signing request")
	}

	fingerprint := cert.Fingerprint
	notAfter := cert.NotAfter.Format(time.RFC3339Nano)
	hostname := req.Msg.Hostname
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

	h.logger.Info("gateway enrolled", "gateway_id", gatewayID, "hostname", req.Msg.Hostname, "not_after", cert.NotAfter)
	return connect.NewResponse(&pm.EnrollGatewayResponse{
		CaCert:      h.ca.CACertPEM(),
		Certificate: cert.CertPEM,
	}), nil
}
