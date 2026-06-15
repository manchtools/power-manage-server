package projectors

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/eventtypes/payloads"
	"github.com/manchtools/power-manage/server/internal/store"
)

// LuksKeyRotatedPayload aliases the shared wire struct so projector
// callers keep their import + symbol; payloads.LuksKeyRotated is the
// canonical handle for handler emit sites.
type LuksKeyRotatedPayload = payloads.LuksKeyRotated

// LuksRevocationPayload is the union shape for the three revocation
// event types (Dispatched, Revoked, Failed). They all UPDATE the
// current row's revocation_status / revocation_at; only Failed sets
// revocation_error. Status is the value the projector writes to the
// row (`dispatched`, `success`, `failed`) — note that the event-type
// suffix and the column value differ for the success case (event is
// `LuksDeviceKeyRevoked`, status is `success`).
type LuksRevocationPayload struct {
	DeviceID string
	ActionID string
	Status   string
	Error    *string
	At       time.Time
}

// LuksKeyRotatedFromEvent decodes LuksKeyRotated. Returns
// ErrIgnoredEvent for any other (stream, event_type) so the listener
// wrapper can silently no-op.
func LuksKeyRotatedFromEvent(e store.PersistedEvent) (LuksKeyRotatedPayload, error) {
	p, err := decodePayload[LuksKeyRotatedPayload](e, "luks_key", eventtypes.LuksKeyRotated)
	if err != nil {
		return LuksKeyRotatedPayload{}, err
	}
	switch {
	case p.DeviceID == "":
		return LuksKeyRotatedPayload{}, fmt.Errorf("projector: LuksKeyRotated requires device_id")
	case p.ActionID == "":
		return LuksKeyRotatedPayload{}, fmt.Errorf("projector: LuksKeyRotated requires action_id")
	case p.DevicePath == "":
		return LuksKeyRotatedPayload{}, fmt.Errorf("projector: LuksKeyRotated requires device_path")
	case p.Passphrase == "":
		return LuksKeyRotatedPayload{}, fmt.Errorf("projector: LuksKeyRotated requires passphrase")
	case p.RotatedAt.IsZero():
		return LuksKeyRotatedPayload{}, fmt.Errorf("projector: LuksKeyRotated requires rotated_at")
	}
	if p.RotationReason == "" {
		// Match the PL/pgSQL `COALESCE(... 'scheduled')` default.
		p.RotationReason = "scheduled"
	}
	return p, nil
}

// LuksRevocationDispatchedFromEvent decodes
// LuksDeviceKeyRevocationDispatched into the union revocation
// payload. Status is hardcoded "dispatched" so the listener doesn't
// need a per-event mapping table.
func LuksRevocationDispatchedFromEvent(e store.PersistedEvent) (LuksRevocationPayload, error) {
	if e.StreamType != "luks_key" || e.EventType != string(eventtypes.LuksDeviceKeyRevocationDispatched) {
		return LuksRevocationPayload{}, ErrIgnoredEvent
	}
	return decodeLuksRevocation(e, "dispatched", "dispatched_at", false)
}

// LuksRevokedFromEvent decodes LuksDeviceKeyRevoked. Status is
// "success" — note the event type vs column-value mismatch is
// intentional and matches the PL/pgSQL projector verbatim.
func LuksRevokedFromEvent(e store.PersistedEvent) (LuksRevocationPayload, error) {
	if e.StreamType != "luks_key" || e.EventType != string(eventtypes.LuksDeviceKeyRevoked) {
		return LuksRevocationPayload{}, ErrIgnoredEvent
	}
	return decodeLuksRevocation(e, "success", "revoked_at", false)
}

// LuksRevocationFailedFromEvent decodes LuksDeviceKeyRevocationFailed
// — only this variant requires an error string in the payload.
func LuksRevocationFailedFromEvent(e store.PersistedEvent) (LuksRevocationPayload, error) {
	if e.StreamType != "luks_key" || e.EventType != string(eventtypes.LuksDeviceKeyRevocationFailed) {
		return LuksRevocationPayload{}, ErrIgnoredEvent
	}
	return decodeLuksRevocation(e, "failed", "failed_at", true)
}

// decodeLuksRevocation centralises the shared (device_id, action_id,
// <its_at>, ?error) parsing for the three revocation variants.
// `atKey` is the JSON key holding the timestamp (different per
// variant — dispatched_at / revoked_at / failed_at). `requireError`
// is true only for the Failed variant; the other two ignore any
// error field that happens to be in the payload.
func decodeLuksRevocation(e store.PersistedEvent, status, atKey string, requireError bool) (LuksRevocationPayload, error) {
	if len(e.Data) == 0 {
		return LuksRevocationPayload{}, fmt.Errorf("projector: empty %s payload", e.EventType)
	}
	// Decode dynamically because the timestamp key name varies per
	// variant. A typed struct per variant would be three near-identical
	// structs for one extra string conversion — not worth it.
	var raw map[string]any
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return LuksRevocationPayload{}, fmt.Errorf("projector: invalid %s payload: %w", e.EventType, err)
	}

	deviceID, _ := raw["device_id"].(string)
	actionID, _ := raw["action_id"].(string)
	atRaw, _ := raw[atKey].(string)
	errStr, _ := raw["error"].(string)

	switch {
	case deviceID == "":
		return LuksRevocationPayload{}, fmt.Errorf("projector: %s requires device_id", e.EventType)
	case actionID == "":
		return LuksRevocationPayload{}, fmt.Errorf("projector: %s requires action_id", e.EventType)
	case atRaw == "":
		return LuksRevocationPayload{}, fmt.Errorf("projector: %s requires %s", e.EventType, atKey)
	case requireError && errStr == "":
		return LuksRevocationPayload{}, fmt.Errorf("projector: %s requires error", e.EventType)
	}

	at, err := time.Parse(time.RFC3339, atRaw)
	if err != nil {
		// Try RFC3339 with nanos as a fallback — agent code uses
		// time.Now().Format(time.RFC3339) but a future emitter may
		// switch to time.RFC3339Nano. Both are valid TIMESTAMPTZ
		// inputs in the deleted PL/pgSQL projector.
		at, err = time.Parse(time.RFC3339Nano, atRaw)
		if err != nil {
			return LuksRevocationPayload{}, fmt.Errorf("projector: %s has invalid %s %q: %w", e.EventType, atKey, atRaw, err)
		}
	}

	out := LuksRevocationPayload{
		DeviceID: deviceID,
		ActionID: actionID,
		Status:   status,
		At:       at,
	}
	if requireError {
		s := errStr
		out.Error = &s
	}
	return out, nil
}
