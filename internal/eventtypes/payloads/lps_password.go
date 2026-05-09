package payloads

import (
	"log/slog"
	"time"
)

// LpsPasswordRotated is the wire shape for LpsPasswordRotated. The
// projector struct in internal/projectors/lps_password.go decodes into
// the same JSON shape; sharing this type at the emit site lets a
// future field rename catch at compile time.
//
// Password is encrypted ciphertext (AES-GCM via internal/crypto) so
// the emitter never holds plaintext at this layer. LogValue still
// masks it defensively in case a future call site routes the whole
// payload through slog.
type LpsPasswordRotated struct {
	DeviceID       string    `json:"device_id"`
	ActionID       string    `json:"action_id"`
	Username       string    `json:"username"`
	Password       string    `json:"password"`
	RotatedAt      time.Time `json:"rotated_at"`
	RotationReason string    `json:"rotation_reason"`
}

// LogValue masks the encrypted Password so a future
// `logger.Warn("…", "payload", payload)` or `fmt.Sprintf("%+v", p)`
// routed through slog cannot leak the credential. Mirrors the
// LpsPasswordRotatedPayload masking in the projector.
func (p LpsPasswordRotated) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("device_id", p.DeviceID),
		slog.String("action_id", p.ActionID),
		slog.String("username", p.Username),
		slog.String("password", "[REDACTED]"),
		slog.Time("rotated_at", p.RotatedAt),
		slog.String("rotation_reason", p.RotationReason),
	)
}
