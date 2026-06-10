package api

import (
	"context"
	"crypto/subtle"
	"log/slog"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/ca"
	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/eventtypes/payloads"
	"github.com/manchtools/power-manage/server/internal/store"
)

// CertificateHandler handles certificate renewal RPCs.
type CertificateHandler struct {
	store  *store.Store
	ca     *ca.CA
	logger *slog.Logger
}

// NewCertificateHandler creates a new certificate handler.
func NewCertificateHandler(st *store.Store, certAuth *ca.CA, logger *slog.Logger) *CertificateHandler {
	return &CertificateHandler{
		store:  st,
		ca:     certAuth,
		logger: logger,
	}
}

// RenewCertificate renews a device certificate.
// The agent authenticates by presenting its current (still valid) certificate.
func (h *CertificateHandler) RenewCertificate(ctx context.Context, req *connect.Request[pm.RenewCertificateRequest]) (*connect.Response[pm.RenewCertificateResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	// Verify the current certificate was issued by our CA
	deviceID, err := h.ca.VerifyCertificate(req.Msg.CurrentCertificate)
	if err != nil {
		h.logger.Warn("certificate verification failed", "error", err)
		return nil, apiErrorCtx(ctx, ErrPermissionDenied, connect.CodePermissionDenied, "invalid certificate")
	}

	// Verify the device exists and is not deleted
	device, err := h.store.Repos().Device.Get(ctx, store.GetDeviceKey{ID: deviceID})
	if err != nil {
		if store.IsNotFound(err) {
			return nil, apiErrorCtx(ctx, ErrDeviceNotFound, connect.CodeNotFound, "device not found")
		}
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to look up device")
	}
	if device.IsDeleted {
		return nil, apiErrorCtx(ctx, ErrDeviceNotFound, connect.CodeNotFound, "device not found")
	}

	// Verify the certificate fingerprint matches what's in the database
	// This prevents use of revoked or superseded certificates
	currentFP, err := ca.FingerprintFromPEM(req.Msg.CurrentCertificate)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to compute fingerprint")
	}
	// Use a constant-time comparison so a co-located attacker can't
	// extract the stored fingerprint byte-by-byte via response-timing
	// (audit F-04). The fingerprints are equal-length hex strings on
	// the happy path; the nil-pointer short-circuit handles the
	// "device never had a cert" case before we reach the compare.
	if device.CertFingerprint == nil ||
		subtle.ConstantTimeCompare([]byte(*device.CertFingerprint), []byte(currentFP)) != 1 {
		h.logger.Warn("certificate fingerprint mismatch",
			"device_id", deviceID,
			"presented", currentFP,
		)
		return nil, apiErrorCtx(ctx, ErrPermissionDenied, connect.CodePermissionDenied, "certificate not recognized")
	}

	// Proof-of-possession: the CSR must carry the SAME public key as the
	// current certificate. The current cert is an untrusted request field on a
	// public (non-mTLS) listener and certs are public material, so without this
	// anyone holding a device's cert PEM could renew it onto a key they control
	// and impersonate the device (#361). Agents reuse their keypair on renewal,
	// so this is behavior-compatible.
	if err := ca.AssertCSRMatchesCertKey(req.Msg.CurrentCertificate, req.Msg.Csr); err != nil {
		h.logger.Warn("certificate renewal proof-of-possession failed", "device_id", deviceID, "error", err)
		return nil, apiErrorCtx(ctx, ErrPermissionDenied, connect.CodePermissionDenied, "CSR key does not match current certificate")
	}

	// Sign the new CSR
	newCert, err := h.ca.IssueCertificateFromCSR(deviceID, req.Msg.Csr)
	if err != nil {
		h.logger.Error("failed to sign CSR", "error", err, "device_id", deviceID)
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to issue certificate")
	}

	// Emit DeviceCertRenewed event (projection handler already exists in migration 001)
	fingerprint := newCert.Fingerprint
	notAfterStr := newCert.NotAfter.Format(time.RFC3339Nano)
	if err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "device",
		StreamID:   deviceID,
		EventType:  string(eventtypes.DeviceCertRenewed),
		Data: payloads.DeviceCertRenewed{
			CertFingerprint: &fingerprint,
			CertNotAfter:    &notAfterStr,
		},
		ActorType: "device",
		ActorID:   deviceID,
	}); err != nil {
		h.logger.Error("failed to append cert renewed event", "error", err, "device_id", deviceID)
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to record certificate renewal")
	}

	h.logger.Info("certificate renewed", "device_id", deviceID, "not_after", newCert.NotAfter)

	return connect.NewResponse(&pm.RenewCertificateResponse{
		Certificate:   newCert.CertPEM,
		NotAfter:      timestamppb.New(newCert.NotAfter),
		CaCertificate: h.ca.CACertPEM(),
	}), nil
}
