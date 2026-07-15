package api

import (
	"context"
	"log/slog"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/crl"
	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/eventtypes/payloads"
	"github.com/manchtools/power-manage/server/internal/store"
)

// crlFreshnessWindow is how long an agent may trust a fetched CRL snapshot
// before it MUST refresh (spec 31 AC12/AC13). The agent fails closed past
// not_after (= fetch time + this window); it is expected to refresh at ≤ half
// this cadence. Short enough that a revocation reaches the fleet quickly.
const crlFreshnessWindow = 1 * time.Hour

// GatewayHandler serves the agent-facing CRL and the operator gateway-revocation
// RPCs (spec 31). Gateway enrollment and renewal live in GatewayAuthHandler and
// InternalHandler respectively; this handler owns the ControlService surface.
type GatewayHandler struct {
	store  *store.Store
	logger *slog.Logger
	// crl is the Valkey-backed revocation list. nil when no Valkey is
	// configured (dev): GetCRL then returns an empty list (matching the
	// internal listener's NoopRevocationChecker dev posture) and revocation
	// returns Unavailable (it cannot take effect without a CRL).
	crl *crl.Store
	// liveness reports which gateway_ids are actually live right now (Valkey
	// registry heartbeat), so ListGateways reflects real liveness rather than
	// the projection's cert-not-expired view. nil in dev / no-Valkey → the list
	// falls back to the not_after view.
	liveness gatewayLiveness
	now      func() time.Time // clock seam; defaults to time.Now, overridden in tests
}

// gatewayLiveness reports the set of currently-live gateway_ids. Satisfied by
// *registry.Registry (ListLiveGatewayIDs); an interface here keeps internal/api
// free of a dependency on internal/gateway/registry.
type gatewayLiveness interface {
	ListLiveGatewayIDs(ctx context.Context) (map[string]struct{}, error)
}

// NewGatewayHandler creates a gateway handler. The CRL store is wired later via
// SetCRLStore once the Valkey subsystem is up.
func NewGatewayHandler(st *store.Store, logger *slog.Logger) *GatewayHandler {
	return &GatewayHandler{store: st, logger: logger, now: time.Now}
}

// SetCRLStore wires the Valkey-backed CRL (post-construction, after Valkey
// comes up).
func (h *GatewayHandler) SetCRLStore(s *crl.Store) { h.crl = s }

// SetGatewayLiveness wires the registry-backed liveness source (post-construction,
// after Valkey is up). When set, ListGateways returns only actually-live
// gateways; when nil it falls back to the not_after view.
func (h *GatewayHandler) SetGatewayLiveness(l gatewayLiveness) { h.liveness = l }

// GetCertificateRevocationList returns the active revoked fingerprints plus a
// freshness window (spec 31 AC13). Agent-facing, rate-limited, served over the
// CA-pinned control channel so the transport authenticates the list — no
// payload signature and no gateway relay.
func (h *GatewayHandler) GetCertificateRevocationList(ctx context.Context, req *connect.Request[pm.GetCertificateRevocationListRequest]) (*connect.Response[pm.GetCertificateRevocationListResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}
	now := h.now()
	fingerprints := []string{}
	if h.crl != nil {
		active, err := h.crl.LoadActive(ctx)
		if err != nil {
			h.logger.Error("failed to load CRL for agent fetch", "error", err)
			return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to load revocation list")
		}
		for fp := range active {
			fingerprints = append(fingerprints, fp)
		}
	} else {
		// Dev/no-Valkey path: serving an empty CRL means every agent believes
		// nothing is revoked. Log so a forgotten CRL wiring in production is
		// observable rather than silently fail-open on the read path.
		h.logger.Warn("serving empty CRL: no CRL store configured on this control instance")
	}
	return connect.NewResponse(&pm.GetCertificateRevocationListResponse{
		RevokedFingerprints: fingerprints,
		NotAfter:            timestamppb.New(now.Add(crlFreshnessWindow)),
		RefreshedAt:         timestamppb.New(now),
	}), nil
}

// RevokeGatewayCertificate revokes an individual gateway's certificate by
// gateway_id (spec 31 AC10). Permission-gated by the interceptor
// (RevokeGatewayCertificate permission) and audit-logged via the GatewayRevoked
// event. The CRL write is the security-critical action and happens FIRST: if it
// fails we never record success, so a "revoked" event can't exist while the
// cert still works (fail-closed).
func (h *GatewayHandler) RevokeGatewayCertificate(ctx context.Context, req *connect.Request[pm.RevokeGatewayCertificateRequest]) (*connect.Response[pm.RevokeGatewayCertificateResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}
	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}
	gatewayID := req.Msg.GatewayId

	row, err := h.store.Queries().GetGatewayFingerprint(ctx, gatewayID)
	if err != nil {
		if store.IsNotFound(err) {
			return nil, apiErrorCtx(ctx, ErrGatewayNotFound, connect.CodeNotFound, "gateway not found")
		}
		h.logger.Error("failed to look up gateway for revocation", "gateway_id", gatewayID, "error", err)
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to look up gateway")
	}

	// Idempotent: an already-revoked gateway is a no-op success. Re-revoking must
	// not emit a duplicate GatewayRevoked audit event; the CRL entry from the
	// original revocation persists until the cert's own expiry.
	if row.RevokedAt != nil {
		return connect.NewResponse(&pm.RevokeGatewayCertificateResponse{}), nil
	}

	if h.crl == nil {
		// No CRL configured — revocation cannot take effect. Fail loudly rather
		// than record a revocation the fleet will never honor.
		h.logger.Error("cannot revoke gateway: no CRL configured", "gateway_id", gatewayID)
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeUnavailable, "certificate revocation is not configured on this control instance")
	}

	// not_after is NOT NULL — revoke the fingerprint until the cert's own expiry
	// (a revoked cert never needs to outlive its expiry on the CRL).
	if err := h.crl.Revoke(ctx, row.Fingerprint, row.NotAfter); err != nil {
		h.logger.Error("failed to add gateway fingerprint to CRL", "gateway_id", gatewayID, "error", err)
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to revoke gateway certificate")
	}

	// Record the revocation (audit + projection revoked_at). The cert is already
	// revoked in the CRL above, so a failure here leaves the cert safely revoked;
	// the operator can retry to get the audit record.
	fingerprint := row.Fingerprint
	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "gateway",
		StreamID:   gatewayID,
		EventType:  string(eventtypes.GatewayRevoked),
		Data:       payloads.GatewayRevoked{Fingerprint: &fingerprint},
		ActorType:  "user",
		ActorID:    userCtx.ID,
	}, "failed to record gateway revocation"); err != nil {
		return nil, err
	}

	h.logger.Info("gateway certificate revoked", "gateway_id", gatewayID, "actor", userCtx.ID)
	return connect.NewResponse(&pm.RevokeGatewayCertificateResponse{}), nil
}

// ListGateways returns currently-live enrolled gateways for the operator view
// (spec 31). Permission-gated (ListGateways) by the interceptor. fingerprint is
// omitted from the response — the UI does not need it.
func (h *GatewayHandler) ListGateways(ctx context.Context, req *connect.Request[pm.ListGatewaysRequest]) (*connect.Response[pm.ListGatewaysResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}
	rows, err := h.store.Queries().ListGateways(ctx)
	if err != nil {
		h.logger.Error("failed to list gateways", "error", err)
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to list gateways")
	}

	// Reflect true liveness (Valkey registry), not just cert-not-expired. A
	// gateway restart re-enrols under a fresh ephemeral id; the old id's cert
	// stays within not_after for ~45 days but its liveness marker TTL-expires in
	// seconds, so filtering on the registry stops departed gateways showing
	// "Active". Fail-open: if liveness is unavailable (dev / Valkey blip) fall
	// back to the not_after view rather than blank the operator's list.
	var live map[string]struct{}
	if h.liveness != nil {
		if l, lerr := h.liveness.ListLiveGatewayIDs(ctx); lerr != nil {
			h.logger.Warn("gateway liveness unavailable; listing all not-yet-expired gateways", "error", lerr)
		} else {
			live = l
		}
	}

	out := make([]*pm.GatewayInfo, 0, len(rows))
	for _, r := range rows {
		if live != nil {
			if _, ok := live[r.GatewayID]; !ok {
				continue // enrolled + cert-valid, but not currently live
			}
		}
		info := &pm.GatewayInfo{
			GatewayId:  r.GatewayID,
			Hostname:   r.Hostname,
			EnrolledAt: timestamppb.New(r.EnrolledAt),
			NotAfter:   timestamppb.New(r.NotAfter),
		}
		if r.RevokedAt != nil {
			info.RevokedAt = timestamppb.New(*r.RevokedAt)
		}
		out = append(out, info)
	}
	return connect.NewResponse(&pm.ListGatewaysResponse{Gateways: out}), nil
}
