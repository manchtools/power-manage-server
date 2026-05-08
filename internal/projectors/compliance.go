package projectors

import (
	"encoding/json"
	"fmt"

	"github.com/manchtools/power-manage/server/internal/store"
)

// ComplianceResultUpdatedPayload mirrors the fields the deleted PL/pgSQL
// project_compliance_event() read out of a ComplianceResultUpdated
// event:
//
//   - device_id, action_id (required, composite-PK columns the UPSERT
//     keys on; missing keys would have surfaced as NOT NULL violations
//     under the PL/pgSQL projector, so we surface that as a
//     decoder-level validation error one layer earlier).
//   - action_name (defaults to "" — matches PL/pgSQL
//     `COALESCE(event.data->>'action_name', "")` for the NOT NULL
//     column. The listener's UPSERT preserves the existing name on
//     replays that omit the key via NULLIF + COALESCE, mirroring the
//     PL/pgSQL `COALESCE(payload, existing.action_name)` semantic).
//   - compliant (defaults to false — matches PL/pgSQL
//     `COALESCE((event.data->>'compliant')::boolean, false)`).
//   - detection_output (raw JSONB sub-tree; PL/pgSQL stored
//     `event.data->'detection_output'` verbatim so a missing key
//     collapses to NULL — json.RawMessage's nil zero value gives the
//     same shape on the Go side).
type ComplianceResultUpdatedPayload struct {
	DeviceID        string
	ActionID        string
	ActionName      string
	Compliant       bool
	DetectionOutput json.RawMessage
}

type complianceResultUpdatedRaw struct {
	DeviceID        string          `json:"device_id"`
	ActionID        string          `json:"action_id"`
	ActionName      *string         `json:"action_name,omitempty"`
	Compliant       *bool           `json:"compliant,omitempty"`
	DetectionOutput json.RawMessage `json:"detection_output,omitempty"`
}

// ComplianceResultUpdatedFromEvent decodes ComplianceResultUpdated.
// Returns ErrIgnoredEvent for any other (stream, event_type) so the
// listener wrapper can silently no-op.
func ComplianceResultUpdatedFromEvent(e store.PersistedEvent) (ComplianceResultUpdatedPayload, error) {
	if e.StreamType != "compliance" || e.EventType != "ComplianceResultUpdated" {
		return ComplianceResultUpdatedPayload{}, ErrIgnoredEvent
	}
	if len(e.Data) == 0 {
		return ComplianceResultUpdatedPayload{}, fmt.Errorf("projector: empty ComplianceResultUpdated payload")
	}
	var raw complianceResultUpdatedRaw
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return ComplianceResultUpdatedPayload{}, fmt.Errorf("projector: invalid ComplianceResultUpdated payload: %w", err)
	}
	if raw.DeviceID == "" {
		return ComplianceResultUpdatedPayload{}, fmt.Errorf("projector: ComplianceResultUpdated requires device_id")
	}
	if raw.ActionID == "" {
		return ComplianceResultUpdatedPayload{}, fmt.Errorf("projector: ComplianceResultUpdated requires action_id")
	}
	out := ComplianceResultUpdatedPayload{
		DeviceID:        raw.DeviceID,
		ActionID:        raw.ActionID,
		DetectionOutput: raw.DetectionOutput,
	}
	if raw.ActionName != nil {
		out.ActionName = *raw.ActionName
	}
	if raw.Compliant != nil {
		out.Compliant = *raw.Compliant
	}
	return out, nil
}

// ComplianceResultRemovedPayload covers ComplianceResultRemoved. Both
// device_id and action_id are required because the DELETE filters on
// the composite PK (no fallback to e.StreamID even though the stream
// id is "deviceID_actionID"; the stream-id format is an emitter-side
// convention and the projector keys off the payload to stay
// agnostic).
type ComplianceResultRemovedPayload struct {
	DeviceID string
	ActionID string
}

type complianceResultRemovedRaw struct {
	DeviceID string `json:"device_id"`
	ActionID string `json:"action_id"`
}

// ComplianceResultRemovedFromEvent decodes ComplianceResultRemoved.
func ComplianceResultRemovedFromEvent(e store.PersistedEvent) (ComplianceResultRemovedPayload, error) {
	if e.StreamType != "compliance" || e.EventType != "ComplianceResultRemoved" {
		return ComplianceResultRemovedPayload{}, ErrIgnoredEvent
	}
	if len(e.Data) == 0 {
		return ComplianceResultRemovedPayload{}, fmt.Errorf("projector: empty ComplianceResultRemoved payload")
	}
	var raw complianceResultRemovedRaw
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return ComplianceResultRemovedPayload{}, fmt.Errorf("projector: invalid ComplianceResultRemoved payload: %w", err)
	}
	if raw.DeviceID == "" {
		return ComplianceResultRemovedPayload{}, fmt.Errorf("projector: ComplianceResultRemoved requires device_id")
	}
	if raw.ActionID == "" {
		return ComplianceResultRemovedPayload{}, fmt.Errorf("projector: ComplianceResultRemoved requires action_id")
	}
	// staticcheck S1016: the raw decode struct has identical field
	// names + types as the payload, so a direct type conversion is
	// the canonical idiom — explicit field-by-field copy would be
	// flagged. Keep the two named types so the JSON tags stay scoped
	// to the wire shape.
	return ComplianceResultRemovedPayload(raw), nil
}
