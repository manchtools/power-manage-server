package projectors

import (
	"encoding/json"
	"fmt"
	"time"

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
// version would have surfaced via the projection_errors table.
type LpsPasswordRotatedPayload struct {
	DeviceID       string    `json:"device_id"`
	ActionID       string    `json:"action_id"`
	Username       string    `json:"username"`
	Password       string    `json:"password"`
	RotatedAt      time.Time `json:"rotated_at"`
	RotationReason string    `json:"rotation_reason"`
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
	if e.StreamType != "lps_password" || e.EventType != "LpsPasswordRotated" {
		return LpsPasswordRotatedPayload{}, ErrIgnoredEvent
	}
	if len(e.Data) == 0 {
		return LpsPasswordRotatedPayload{}, fmt.Errorf("projector: empty LpsPasswordRotated payload")
	}
	var p LpsPasswordRotatedPayload
	if err := json.Unmarshal(e.Data, &p); err != nil {
		return LpsPasswordRotatedPayload{}, fmt.Errorf("projector: invalid LpsPasswordRotated payload: %w", err)
	}
	if p.DeviceID == "" || p.Username == "" {
		return LpsPasswordRotatedPayload{}, fmt.Errorf("projector: LpsPasswordRotated requires device_id + username")
	}
	if p.RotationReason == "" {
		// Match the PL/pgSQL `COALESCE(... 'scheduled')` default so
		// rows inserted from older agents that omit the field stay
		// indistinguishable from PL/pgSQL-projected rows.
		p.RotationReason = "scheduled"
	}
	return p, nil
}
