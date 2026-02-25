package api

import (
	"context"
	"log/slog"
	"time"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/types/known/timestamppb"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/ca"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
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
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	// Verify the current certificate was issued by our CA
	deviceID, err := h.ca.VerifyCertificate(req.Msg.CurrentCertificate)
	if err != nil {
		h.logger.Warn("certificate verification failed", "error", err)
		return nil, apiError(ErrPermissionDenied, connect.CodePermissionDenied, "invalid certificate")
	}

	// Verify the device exists and is not deleted
	device, err := h.store.Queries().GetDeviceByID(ctx, db.GetDeviceByIDParams{
		ID: deviceID,
	})
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, apiError(ErrDeviceNotFound, connect.CodeNotFound, "device not found")
		}
		return nil, apiError(ErrInternal, connect.CodeInternal, "failed to look up device")
	}
	if device.IsDeleted {
		return nil, apiError(ErrDeviceNotFound, connect.CodeNotFound, "device not found")
	}

	// Verify the certificate fingerprint matches what's in the database
	// This prevents use of revoked or superseded certificates
	currentFP, err := ca.FingerprintFromPEM(req.Msg.CurrentCertificate)
	if err != nil {
		return nil, apiError(ErrInternal, connect.CodeInternal, "failed to compute fingerprint")
	}
	if device.CertFingerprint == nil || *device.CertFingerprint != currentFP {
		h.logger.Warn("certificate fingerprint mismatch",
			"device_id", deviceID,
			"presented", currentFP,
		)
		return nil, apiError(ErrPermissionDenied, connect.CodePermissionDenied, "certificate not recognized")
	}

	// Sign the new CSR
	newCert, err := h.ca.IssueCertificateFromCSR(deviceID, req.Msg.Csr)
	if err != nil {
		h.logger.Error("failed to sign CSR", "error", err, "device_id", deviceID)
		return nil, apiError(ErrInternal, connect.CodeInternal, "failed to issue certificate")
	}

	// Emit DeviceCertRenewed event (projection handler already exists in migration 001)
	if err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "device",
		StreamID:   deviceID,
		EventType:  "DeviceCertRenewed",
		Data: map[string]any{
			"cert_fingerprint": newCert.Fingerprint,
			"cert_not_after":   newCert.NotAfter.Format(time.RFC3339),
		},
		ActorType: "device",
		ActorID:   deviceID,
	}); err != nil {
		h.logger.Error("failed to append cert renewed event", "error", err, "device_id", deviceID)
		return nil, apiError(ErrInternal, connect.CodeInternal, "failed to record certificate renewal")
	}

	h.logger.Info("certificate renewed", "device_id", deviceID, "not_after", newCert.NotAfter)

	return connect.NewResponse(&pm.RenewCertificateResponse{
		Certificate: newCert.CertPEM,
		NotAfter:    timestamppb.New(newCert.NotAfter),
	}), nil
}
