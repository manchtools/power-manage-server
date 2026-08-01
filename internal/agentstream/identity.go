package agentstream

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/manchtools/power-manage/server/internal/ca"
	"github.com/manchtools/power-manage/server/internal/mtls"
)

type deviceIdentityKey struct{}

// WithDeviceID binds the device identity already authenticated by the mTLS
// listener to an AgentService request context.
func WithDeviceID(ctx context.Context, deviceID string) context.Context {
	return context.WithValue(ctx, deviceIdentityKey{}, deviceID)
}

// DeviceIDFromContext returns the mTLS-authenticated device identity.
func DeviceIDFromContext(ctx context.Context) (string, bool) {
	if ctx == nil {
		return "", false
	}
	deviceID, ok := ctx.Value(deviceIdentityKey{}).(string)
	return deviceID, ok
}

type writeDeadlinerKey struct{}

type writeDeadliner interface {
	SetWriteDeadline(time.Time) error
}

func withWriteDeadliner(ctx context.Context, deadliner writeDeadliner) context.Context {
	return context.WithValue(ctx, writeDeadlinerKey{}, deadliner)
}

func writeDeadlinerFrom(ctx context.Context) writeDeadliner {
	if ctx == nil {
		return nil
	}
	deadliner, _ := ctx.Value(writeDeadlinerKey{}).(writeDeadliner)
	return deadliner
}

// MTLSMiddleware authenticates AgentService requests and binds the verified
// certificate identity into their contexts. Revocation lookup failures reject
// the request; there is no queue-backed CRL or permissive fallback.
func MTLSMiddleware(next http.Handler, revocation mtls.RevocationChecker, logger *slog.Logger) http.Handler {
	if next == nil {
		panic("agentstream: mTLS middleware requires a handler")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/health" || request.URL.Path == "/ready" {
			next.ServeHTTP(w, request)
			return
		}
		deviceID, err := mtls.DeviceIDFromRequest(request)
		if err != nil {
			http.Error(w, "client certificate required", http.StatusUnauthorized)
			return
		}
		peerClass, err := mtls.PeerClassFromTLS(request.TLS)
		if err != nil || peerClass != mtls.PeerClassAgent {
			http.Error(w, "agent certificate required", http.StatusForbidden)
			return
		}
		if revocation == nil {
			logger.Error("reject agent mTLS without revocation checker", "device_id", deviceID)
			http.Error(w, "certificate revocation unavailable", http.StatusForbidden)
			return
		}
		if len(request.TLS.PeerCertificates) == 0 {
			http.Error(w, "client certificate required", http.StatusUnauthorized)
			return
		}
		fingerprint := ca.FingerprintFromCert(request.TLS.PeerCertificates[0])
		revoked, err := revocation.IsRevoked(request.Context(), fingerprint)
		if err != nil {
			logger.Error("reject agent mTLS after revocation lookup failure", "device_id", deviceID, "error", err)
			http.Error(w, "certificate revocation unavailable", http.StatusForbidden)
			return
		}
		if revoked {
			http.Error(w, "certificate revoked", http.StatusForbidden)
			return
		}
		ctx := WithDeviceID(request.Context(), deviceID)
		controller := http.NewResponseController(w)
		if err := controller.SetWriteDeadline(time.Time{}); err == nil || !errors.Is(err, http.ErrNotSupported) {
			ctx = withWriteDeadliner(ctx, controller)
		}
		next.ServeHTTP(w, request.WithContext(ctx))
	})
}
