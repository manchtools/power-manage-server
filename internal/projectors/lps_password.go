package projectors

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/store"
)

// LpsPasswordRotatedPayload covers every field the lps_password
// projector reads from the LpsPasswordRotated event. The agent sends
// rotated_at as an RFC 3339 string (see sdk/proto/pm/v1/internal.proto
// LpsRotation.rotated_at), so json.Unmarshal into time.Time round-trips
// natively.
//
// The deleted PL/pgSQL projector cast `(event.data->>'rotated_at')::TIMESTAMPTZ`
// directly. Pre-parsing in Go preserves the same shape: a parse error
// here is the analogue of a Postgres cast failure, which the PL/pgSQL
// version would have surfaced via the plpgsql_projection_errors table.
type LpsPasswordRotatedPayload struct {
	DeviceID       string    `json:"device_id"`
	ActionID       string    `json:"action_id"`
	Username       string    `json:"username"`
	Password       string    `json:"password"`
	RotatedAt      time.Time `json:"rotated_at"`
	RotationReason string    `json:"rotation_reason"`
}

// LogValue implements slog.LogValuer so the encrypted Password is
// never written verbatim by structured logs. The listener body
// already logs only individual non-secret fields, but a future
// `logger.Warn("…", "payload", payload)` or `fmt.Sprintf("%+v", p)`
// routed through slog would otherwise leak the credential. Mask at
// the type level so the safety holds regardless of caller
// discipline.
func (p LpsPasswordRotatedPayload) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("device_id", p.DeviceID),
		slog.String("action_id", p.ActionID),
		slog.String("username", p.Username),
		slog.String("password", "[REDACTED]"),
		slog.Time("rotated_at", p.RotatedAt),
		slog.String("rotation_reason", p.RotationReason),
	)
}

// LpsPasswordRotatedFromEvent decodes the event payload into the
// typed shape the listener writes. Returns ErrIgnoredEvent for any
// event the lps_password projector does not act on so the listener
// wrapper can silently no-op.
//
// Pure: no I/O, deterministic, depends only on the event's fields.
// Reuse from a handler that wants to mirror the projection state in
// memory while the listener writes to the DB.
func LpsPasswordRotatedFromEvent(e store.PersistedEvent) (LpsPasswordRotatedPayload, error) {
	if e.StreamType != "lps_password" || e.EventType != string(eventtypes.LpsPasswordRotated) {
		return LpsPasswordRotatedPayload{}, ErrIgnoredEvent
	}
	if len(e.Data) == 0 {
		return LpsPasswordRotatedPayload{}, fmt.Errorf("projector: empty LpsPasswordRotated payload")
	}
	var p LpsPasswordRotatedPayload
	if err := json.Unmarshal(e.Data, &p); err != nil {
		return LpsPasswordRotatedPayload{}, fmt.Errorf("projector: invalid LpsPasswordRotated payload: %w", err)
	}
	// Every field below was implicitly required by the deleted
	// PL/pgSQL projector — `(event.data->>'rotated_at')::TIMESTAMPTZ`
	// would have raised on a missing value, and the inserted row is
	// useless without the device/action/username/password tuple.
	// Validating up front keeps the failure surface in the listener's
	// log rather than producing silently-bad projection rows that
	// outlast the event log.
	switch {
	case p.DeviceID == "":
		return LpsPasswordRotatedPayload{}, fmt.Errorf("projector: LpsPasswordRotated requires device_id")
	case p.ActionID == "":
		return LpsPasswordRotatedPayload{}, fmt.Errorf("projector: LpsPasswordRotated requires action_id")
	case p.Username == "":
		return LpsPasswordRotatedPayload{}, fmt.Errorf("projector: LpsPasswordRotated requires username")
	case p.Password == "":
		return LpsPasswordRotatedPayload{}, fmt.Errorf("projector: LpsPasswordRotated requires password")
	case p.RotatedAt.IsZero():
		return LpsPasswordRotatedPayload{}, fmt.Errorf("projector: LpsPasswordRotated requires rotated_at")
	}
	if p.RotationReason == "" {
		// Match the PL/pgSQL `COALESCE(... 'scheduled')` default so
		// rows inserted from older agents that omit the field stay
		// indistinguishable from PL/pgSQL-projected rows.
		p.RotationReason = "scheduled"
	}
	return p, nil
}
