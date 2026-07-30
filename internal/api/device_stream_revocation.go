package api

import (
	"context"
	"log/slog"

	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/store"
)

// streamCloser drops a device's live agent stream. connection.Manager satisfies
// it; the narrow interface keeps this package independent of the stream layer
// and lets a test assert the call without a real connection.
type streamCloser interface {
	Unregister(deviceID string)
}

// DeviceStreamRevocationListener terminates a device's live stream when its
// certificate is revoked — spec 41 criterion 5.
//
// Revoking a certificate stops the NEXT handshake. It does nothing to a stream
// that is already established, because the certificate was checked when that
// connection opened and is never re-examined for its lifetime. Agent streams are
// long-lived by design, so without this a superseded or deleted device keeps a
// fully privileged connection until it happens to disconnect — which for a
// healthy agent may be never.
//
// Registered as a POST-COMMIT listener, and that ordering is the point. The
// revocation row and the event are written in one transaction (criterion 6); if
// the stream were dropped before that commit, a rolled-back transaction would
// have disconnected a device whose certificate is still perfectly valid. Closing
// after the commit means the disconnect only ever follows a revocation that
// actually happened.
//
// Both triggers matter for different reasons:
//
//   - DeviceCertRenewed: the live stream is authenticated with the certificate
//     that renewal just superseded. Dropping it forces an immediate reconnect
//     under the new one, so the old certificate stops being usable in practice
//     and not merely in principle.
//   - DeviceDeleted: the device is gone; a still-connected agent must not keep
//     receiving dispatches or reporting results for a device that no longer
//     exists.
//
// Best-effort by construction: Unregister on a device with no live stream is a
// no-op, so a device that was never connected costs nothing.
func DeviceStreamRevocationListener(conns streamCloser, logger *slog.Logger) store.EventListener {
	return func(_ context.Context, ev store.PersistedEvent) {
		if ev.StreamType != "device" {
			return
		}
		switch ev.EventType {
		case string(eventtypes.DeviceCertRenewed), string(eventtypes.DeviceDeleted):
		default:
			return
		}
		if conns == nil {
			return
		}
		conns.Unregister(ev.StreamID)
		logger.Info("terminated live agent stream after certificate revocation",
			"device_id", ev.StreamID, "event_type", ev.EventType)
	}
}
