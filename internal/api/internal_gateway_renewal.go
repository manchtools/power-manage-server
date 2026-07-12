package api

import (
	"context"
	"encoding/pem"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/ca"
	"github.com/manchtools/power-manage/server/internal/crl"
	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/eventtypes/payloads"
	"github.com/manchtools/power-manage/server/internal/mtls"
	"github.com/manchtools/power-manage/server/internal/store"
)

// SetGatewayRenewal wires the CA and CRL the gateway-certificate renewal path
// needs: the CA to re-sign, the CRL to revoke the superseded fingerprint.
// Called from main.go. Both nil until wired; RenewGatewayCertificate fails
// closed without them.
func (h *InternalHandler) SetGatewayRenewal(certAuth *ca.CA, crlStore *crl.Store) {
	h.gatewayCA = certAuth
	h.gatewayCRL = crlStore
}

// RenewGatewayCertificate re-signs a gateway's cert before expiry (spec 31
// Part B). The caller authenticates with its CURRENT gateway cert over the
// control-facing mTLS plane; gateway_id is read from that authenticated peer
// cert's CN, never a request field. The internal listener's
// RequirePeerClassNotRevoked middleware has already proven the peer is a
// non-revoked gateway class, so this handler only needs proof-of-possession and
// re-issuance.
func (h *InternalHandler) RenewGatewayCertificate(ctx context.Context, req *connect.Request[pm.RenewGatewayCertificateRequest]) (*connect.Response[pm.RenewGatewayCertificateResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}
	if h.gatewayCA == nil {
		h.logger.Error("gateway renewal not configured (no CA wired)")
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "gateway renewal is not configured")
	}

	// gateway_id is the authenticated peer cert CN. Absent → the listener
	// middleware was not wired; reject rather than trust a request field.
	peerCert, ok := mtls.PeerCertFromContext(ctx)
	if !ok {
		h.logger.Warn("gateway renewal denied: no authenticated peer certificate")
		return nil, apiErrorCtx(ctx, ErrPermissionDenied, connect.CodePermissionDenied, "certificate renewal denied")
	}
	gatewayID := peerCert.Subject.CommonName
	if gatewayID == "" {
		h.logger.Warn("gateway renewal denied: peer certificate has no CN")
		return nil, apiErrorCtx(ctx, ErrPermissionDenied, connect.CodePermissionDenied, "certificate renewal denied")
	}

	// Defense in depth: the middleware already gates PeerClassGateway, but verify
	// again from the cert we hold so this handler is correct even if the mount
	// order regresses.
	class, err := mtls.PeerClassFromCert(peerCert)
	if err != nil || class != mtls.PeerClassGateway {
		h.logger.Warn("gateway renewal denied: peer is not a gateway", "gateway_id", gatewayID, "class", class, "error", err)
		return nil, apiErrorCtx(ctx, ErrPermissionDenied, connect.CodePermissionDenied, "certificate renewal denied")
	}

	// Proof-of-possession: the new CSR must carry the same public key as the
	// presented (current) cert — the renewer must hold the current private key.
	currentCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: peerCert.Raw})
	if err := ca.AssertCSRMatchesCertKey(currentCertPEM, req.Msg.Csr); err != nil {
		h.logger.Warn("gateway renewal proof-of-possession failed", "gateway_id", gatewayID, "error", err)
		return nil, apiErrorCtx(ctx, ErrPermissionDenied, connect.CodePermissionDenied, "certificate renewal denied")
	}

	// Preserve the gateway's DNS SAN (hostname) across renewal — it is what the
	// agent's standard TLS verification matches. The current cert carries it
	// (stamped at enrollment); re-stamp the same name. A current cert with NO
	// DNS SAN predates the DNS-SAN fix; the renewed cert would be unverifiable by
	// agents, so warn — the operator should re-enroll (which is a restart away,
	// gateway identity being ephemeral-per-boot) rather than renew.
	var hostname string
	if len(peerCert.DNSNames) > 0 {
		hostname = peerCert.DNSNames[0]
	} else {
		h.logger.Warn("gateway renewal: current cert has no DNS SAN; the renewed cert will be unverifiable by agents — re-enroll instead", "gateway_id", gatewayID)
	}
	newCert, err := h.gatewayCA.IssueGatewayCertificateFromCSR(gatewayID, req.Msg.Csr, hostname)
	if err != nil {
		h.logger.Warn("gateway renewal: CSR rejected", "gateway_id", gatewayID, "error", err)
		return nil, apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "invalid certificate signing request")
	}

	// Record the renewal (audit + projection advance) BEFORE revoking the old
	// cert, so the projection's fingerprint is the new one before the old
	// fingerprint lands on the CRL.
	fingerprint := newCert.Fingerprint
	notAfterStr := newCert.NotAfter.Format(time.RFC3339Nano)
	if err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "gateway",
		StreamID:   gatewayID,
		EventType:  string(eventtypes.GatewayCertRenewed),
		Data: payloads.GatewayCertRenewed{
			Fingerprint: &fingerprint,
			NotAfter:    &notAfterStr,
		},
		ActorType: "gateway",
		ActorID:   gatewayID,
	}); err != nil {
		h.logger.Error("failed to append GatewayCertRenewed event", "gateway_id", gatewayID, "error", err)
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to record certificate renewal")
	}

	// Revoke the superseded cert so it stops being accepted immediately (it would
	// otherwise remain valid for its full 45-day lifetime). Best-effort — the
	// renewal already committed; a CRL failure is logged and the next
	// renewal/refresh re-converges.
	if h.gatewayCRL != nil {
		oldFP := ca.FingerprintFromCert(peerCert)
		if err := h.gatewayCRL.Revoke(ctx, oldFP, peerCert.NotAfter); err != nil {
			h.logger.Error("failed to revoke superseded gateway cert in CRL", "gateway_id", gatewayID, "error", err)
		}
	}

	h.logger.Info("gateway certificate renewed", "gateway_id", gatewayID, "not_after", newCert.NotAfter)
	return connect.NewResponse(&pm.RenewGatewayCertificateResponse{
		Certificate: newCert.CertPEM,
		NotAfter:    timestamppb.New(newCert.NotAfter),
	}), nil
}
