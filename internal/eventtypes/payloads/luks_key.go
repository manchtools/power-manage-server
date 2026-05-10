package payloads

import (
	"log/slog"
	"time"
)

// LuksKeyRotated is the wire shape for LuksKeyRotated. Same pattern as
// LpsPasswordRotated but partitioned by device_path.
type LuksKeyRotated struct {
	DeviceID       string    `json:"device_id"`
	ActionID       string    `json:"action_id"`
	DevicePath     string    `json:"device_path"`
	Passphrase     string    `json:"passphrase"`
	RotatedAt      time.Time `json:"rotated_at"`
	RotationReason string    `json:"rotation_reason"`
}

// LogValue masks the encrypted Passphrase. See LpsPasswordRotated for
// the rationale.
func (p LuksKeyRotated) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("device_id", p.DeviceID),
		slog.String("action_id", p.ActionID),
		slog.String("device_path", p.DevicePath),
		slog.String("passphrase", "[REDACTED]"),
		slog.Time("rotated_at", p.RotatedAt),
		slog.String("rotation_reason", p.RotationReason),
	)
}

// LuksDeviceKeyRevocationRequested is the wire shape for the
// LuksDeviceKeyRevocationRequested event. Phase 1 of the three-phase
// revocation audit (Requested -> (Dispatched|Failed) -> Revoked|Failed)
// — appended BEFORE the Asynq enqueue so operator intent is durable
// even if the queue is unreachable.
//
// All three fields are required; the projector intentionally no-ops on
// this event today (the projection only transitions on Dispatched /
// Failed / Revoked) but the row stays in the audit log.
type LuksDeviceKeyRevocationRequested struct {
	DeviceID    string `json:"device_id"`
	ActionID    string `json:"action_id"`
	RequestedAt string `json:"requested_at"`
}

// LuksDeviceKeyRevocationFailed is the wire shape for
// LuksDeviceKeyRevocationFailed. Phase 3b — appended when Asynq
// enqueue fails (control-server emit) or when the agent reports
// revocation failure (gateway/inbox emit). The projector reads
// device_id, action_id, error, and failed_at; failed_at must be
// RFC 3339 (or RFC 3339 with nanos) per the projector decoder
// fallback.
type LuksDeviceKeyRevocationFailed struct {
	DeviceID string `json:"device_id"`
	ActionID string `json:"action_id"`
	Error    string `json:"error"`
	FailedAt string `json:"failed_at"`
}

// LuksDeviceKeyRevocationDispatched is the wire shape for
// LuksDeviceKeyRevocationDispatched. Phase 3a — appended after the
// Asynq enqueue succeeds. The projector flips revocation_status to
// "dispatched" using dispatched_at as the revocation_at timestamp.
type LuksDeviceKeyRevocationDispatched struct {
	DeviceID     string `json:"device_id"`
	ActionID     string `json:"action_id"`
	DispatchedAt string `json:"dispatched_at"`
}

// LuksDeviceKeyRevoked is the wire shape for the terminal-success
// revocation event the inbox worker emits when the agent reports
// success. The projector flips revocation_status to "success" and
// stores revoked_at as the revocation_at timestamp.
type LuksDeviceKeyRevoked struct {
	DeviceID  string `json:"device_id"`
	ActionID  string `json:"action_id"`
	RevokedAt string `json:"revoked_at"`
}
