package projectors

import (
	"encoding/json"
	"fmt"

	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/eventtypes/payloads"
	"github.com/manchtools/power-manage/server/internal/store"
)

// LpsPasswordRotatedPayload aliases the shared wire struct so existing
// projector callers keep their import + symbol. The Payload-suffix name
// stays for projector-side code; the bare payloads.LpsPasswordRotated
// is the canonical handle for handler emit sites.
type LpsPasswordRotatedPayload = payloads.LpsPasswordRotated

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
