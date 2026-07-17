package api

import (
	"context"
	"crypto/subtle"
	"errors"
	"hash/fnv"
	"log/slog"
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

// CertificateHandler handles certificate renewal RPCs.
type CertificateHandler struct {
	store  *store.Store
	ca     *ca.CA
	logger *slog.Logger
	// crl, when set, receives the superseded fingerprint on renewal so the
	// old cert stops working at the gateway (revocation). nil disables it
	// (no Valkey configured / tests).
	crl *crl.Store
}

// NewCertificateHandler creates a new certificate handler.
func NewCertificateHandler(st *store.Store, certAuth *ca.CA, logger *slog.Logger) *CertificateHandler {
	return &CertificateHandler{
		store:  st,
		ca:     certAuth,
		logger: logger,
	}
}

// SetCRLStore wires the certificate revocation list (post-construction, after
// the Valkey subsystem comes up).
func (h *CertificateHandler) SetCRLStore(s *crl.Store) { h.crl = s }

// renewCertTestHook is a test-only seam invoked between the fingerprint check
// and the certificate issuance/append in renewLocked. It is nil (a no-op) in
// production; tests install it via SetRenewCertTestHook (export_test.go) to
// widen the read→append window and prove the per-device advisory lock actually
// serializes concurrent renewals.
var renewCertTestHook func()

// renewCertLockNamespace namespaces the per-device certificate-renewal advisory
// lock so its derived keys cannot collide with the admin-mutation lock
// (advisoryKeyAdminMutation) or the dynamic-group locks. "cert" in hex occupies
// the high 32 bits; the low 32 bits are an FNV-1a hash of the device id. A hash
// collision only serializes two unrelated devices' renewals occasionally —
// correctness-preserving, never a wrong outcome.
const renewCertLockNamespace int64 = 0x63657274 << 32 // "cert"

func renewCertLockKey(deviceID string) int64 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(deviceID))
	return renewCertLockNamespace | int64(h.Sum32())
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

	// Serialize renewals per device (CF6). The fingerprint read+compare and the
	// DeviceCertRenewed append run together under a per-device advisory lock, so
	// two concurrent renewals presenting the same current certificate cannot
	// both pass the check and both issue a cert (which would leave a valid-but-
	// untracked live cert whose fingerprint never lands in the projection). The
	// second caller blocks, then re-reads the advanced fingerprint and is
	// rejected. WithAdvisoryLock holds the lock across the post-commit
	// projection write, so the next caller's Device.Get observes it.
	var resp *connect.Response[pm.RenewCertificateResponse]
	lockErr := h.store.WithAdvisoryLock(ctx, renewCertLockKey(deviceID), func() error {
		r, rerr := h.renewLocked(ctx, deviceID, req.Msg)
		if rerr != nil {
			return rerr
		}
		resp = r
		return nil
	})
	if lockErr != nil {
		// renewLocked returns connect-coded errors; pass those through. Only a
		// lock-infrastructure failure (acquire/release) is re-coded Internal.
		var ce *connect.Error
		if errors.As(lockErr, &ce) {
			return nil, lockErr
		}
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to serialize certificate renewal")
	}
	return resp, nil
}

// renewLocked performs the device lookup, fingerprint and proof-of-possession
// checks, issuance, DeviceCertRenewed append and superseded-cert revocation. It
// MUST run while holding the per-device renewal advisory lock (see
// RenewCertificate) so the fingerprint read and the append are atomic against a
// concurrent renewal.
func (h *CertificateHandler) renewLocked(ctx context.Context, deviceID string, msg *pm.RenewCertificateRequest) (*connect.Response[pm.RenewCertificateResponse], error) {
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
	currentFP, err := ca.FingerprintFromPEM(msg.CurrentCertificate)
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

	// Test seam: widen the window between the fingerprint check and the append
	// so the concurrency regression test can prove the advisory lock serializes
	// renewals. No-op in production.
	if renewCertTestHook != nil {
		renewCertTestHook()
	}

	// Defense-in-depth (audit L2): assert the presented cert is agent-class
	// before re-issuing an agent-class cert. RenewCertificate only ever mints
	// agent certs, so a non-agent peer (e.g. a leaked gateway cert, same CA +
	// ClientAuth EKU) must not be renewable here. Today it is caught downstream
	// (a gateway ULID isn't in the device table → NotFound), but that safety
	// rests entirely on the device lookup; pin the class at the boundary so a
	// future change that seeds gateway IDs into the device table can't turn this
	// into a class-confusion re-issue.
	presentedClass, err := ca.PeerClassFromPEM(msg.CurrentCertificate)
	if err != nil || presentedClass != mtls.PeerClassAgent {
		h.logger.Warn("certificate renewal rejected: presented cert is not agent-class",
			"device_id", deviceID, "peer_class", presentedClass, "error", err)
		return nil, apiErrorCtx(ctx, ErrPermissionDenied, connect.CodePermissionDenied, "certificate not recognized")
	}

	// Proof-of-possession: the CSR must carry the SAME public key as the
	// current certificate. The current cert is an untrusted request field on a
	// public (non-mTLS) listener and certs are public material, so without this
	// anyone holding a device's cert PEM could renew it onto a key they control
	// and impersonate the device (#361). Agents reuse their keypair on renewal,
	// so this is behavior-compatible.
	if err := ca.AssertCSRMatchesCertKey(msg.CurrentCertificate, msg.Csr); err != nil {
		h.logger.Warn("certificate renewal proof-of-possession failed", "device_id", deviceID, "error", err)
		return nil, apiErrorCtx(ctx, ErrPermissionDenied, connect.CodePermissionDenied, "CSR key does not match current certificate")
	}

	// Sign the new CSR
	newCert, err := h.ca.IssueCertificateFromCSR(deviceID, msg.Csr)
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

	// Revoke the superseded cert: add its fingerprint to the CRL until its own
	// expiry, so a gateway stops admitting the old cert immediately (it would
	// otherwise stay valid for its full year). Best-effort — a CRL failure must
	// not fail the renewal the agent already committed to; it's logged and the
	// next renewal/the periodic refresh re-converge. The DB fingerprint was
	// already advanced by the DeviceCertRenewed event above.
	if h.crl != nil {
		if oldNotAfter, err := ca.NotAfterFromPEM(msg.CurrentCertificate); err != nil {
			h.logger.Warn("could not parse old cert expiry for CRL; superseded cert not revoked", "device_id", deviceID, "error", err)
		} else if err := h.crl.Revoke(ctx, currentFP, oldNotAfter); err != nil {
			h.logger.Error("failed to revoke superseded cert in CRL", "device_id", deviceID, "error", err)
		}
	}

	h.logger.Info("certificate renewed", "device_id", deviceID, "not_after", newCert.NotAfter)

	return connect.NewResponse(&pm.RenewCertificateResponse{
		Certificate:   newCert.CertPEM,
		NotAfter:      timestamppb.New(newCert.NotAfter),
		CaCertificate: h.ca.CACertPEM(),
	}), nil
}
