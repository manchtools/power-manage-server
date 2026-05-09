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
