package projectors

import (
	"encoding/json"
	"fmt"

	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/store"
)

// AssignmentCreatedPayload mirrors the fields the deleted PL/pgSQL
// project_assignment_event() read out of an AssignmentCreated event:
//
//   - source_type / source_id (required, NOT NULL columns)
//   - target_type / target_id (required, NOT NULL columns)
//   - sort_order (defaults to 0 to match the PL/pgSQL
//     `COALESCE((event.data->>'sort_order')::INTEGER, 0)`)
//   - mode (defaults to 0 to match the PL/pgSQL
//     `COALESCE((event.data->>'mode')::INTEGER, 0)`; mode 0 = REQUIRED)
type AssignmentCreatedPayload struct {
	ID         string
	SourceType string
	SourceID   string
	TargetType string
	TargetID   string
	SortOrder  int32
	Mode       int32
	CreatedBy  string
}

type assignmentCreatedRaw struct {
	SourceType string `json:"source_type"`
	SourceID   string `json:"source_id"`
	TargetType string `json:"target_type"`
	TargetID   string `json:"target_id"`
	SortOrder  *int32 `json:"sort_order,omitempty"`
	Mode       *int32 `json:"mode,omitempty"`
}

// AssignmentCreatedFromEvent decodes AssignmentCreated. Returns
// ErrIgnoredEvent for any other (stream, event_type) so the listener
// wrapper can silently no-op.
//
// The four tuple fields (source_type/id + target_type/id) are required
// because the underlying NOT NULL columns would otherwise fail the
// INSERT, surfacing as a Postgres constraint violation rather than a
// projector-level validation error. Pre-validating here keeps the
// failure surface in the listener log instead of producing a half-
// applied row.
func AssignmentCreatedFromEvent(e store.PersistedEvent) (AssignmentCreatedPayload, error) {
	if e.StreamType != "assignment" || e.EventType != string(eventtypes.AssignmentCreated) {
		return AssignmentCreatedPayload{}, ErrIgnoredEvent
	}
	if len(e.Data) == 0 {
		return AssignmentCreatedPayload{}, fmt.Errorf("projector: empty AssignmentCreated payload")
	}
	var raw assignmentCreatedRaw
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return AssignmentCreatedPayload{}, fmt.Errorf("projector: invalid AssignmentCreated payload: %w", err)
	}
	switch {
	case raw.SourceType == "":
		return AssignmentCreatedPayload{}, fmt.Errorf("projector: AssignmentCreated requires source_type")
	case raw.SourceID == "":
		return AssignmentCreatedPayload{}, fmt.Errorf("projector: AssignmentCreated requires source_id")
	case raw.TargetType == "":
		return AssignmentCreatedPayload{}, fmt.Errorf("projector: AssignmentCreated requires target_type")
	case raw.TargetID == "":
		return AssignmentCreatedPayload{}, fmt.Errorf("projector: AssignmentCreated requires target_id")
	}
	out := AssignmentCreatedPayload{
		ID:         e.StreamID,
		SourceType: raw.SourceType,
		SourceID:   raw.SourceID,
		TargetType: raw.TargetType,
		TargetID:   raw.TargetID,
		CreatedBy:  e.ActorID,
	}
	if raw.SortOrder != nil {
		out.SortOrder = *raw.SortOrder
	}
	if raw.Mode != nil {
		out.Mode = *raw.Mode
	}
	return out, nil
}

// AssignmentModeChangedPayload mirrors the single field the PL/pgSQL
// projector wrote on AssignmentModeChanged. Missing mode defaults to
// 0 (matches the PL/pgSQL `COALESCE((event.data->>'mode')::INTEGER, 0)`).
//
// AssignmentModeChanged is not currently emitted (the project's
// mutation model is "assignments are immutable; mutate by delete-and-
// recreate"), but the projector keeps parity with the PL/pgSQL version
// so any historical events in production event stores still replay
// cleanly during a rebuild.
type AssignmentModeChangedPayload struct {
	ID   string
	Mode int32
}

type assignmentModeChangedRaw struct {
	Mode *int32 `json:"mode,omitempty"`
}

// AssignmentModeChangedFromEvent decodes AssignmentModeChanged.
func AssignmentModeChangedFromEvent(e store.PersistedEvent) (AssignmentModeChangedPayload, error) {
	if e.StreamType != "assignment" || e.EventType != string(eventtypes.AssignmentModeChanged) {
		return AssignmentModeChangedPayload{}, ErrIgnoredEvent
	}
	out := AssignmentModeChangedPayload{ID: e.StreamID}
	if len(e.Data) == 0 {
		return out, nil
	}
	var raw assignmentModeChangedRaw
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return AssignmentModeChangedPayload{}, fmt.Errorf("projector: invalid AssignmentModeChanged payload: %w", err)
	}
	if raw.Mode != nil {
		out.Mode = *raw.Mode
	}
	return out, nil
}

// AssignmentSortOrderChangedPayload mirrors the single field the
// PL/pgSQL projector wrote on AssignmentSortOrderChanged. Missing
// sort_order defaults to 0.
//
// Like AssignmentModeChanged, this event is not currently emitted but
// the projector preserves parity for replay safety.
type AssignmentSortOrderChangedPayload struct {
	ID        string
	SortOrder int32
}

type assignmentSortOrderChangedRaw struct {
	SortOrder *int32 `json:"sort_order,omitempty"`
}

// AssignmentSortOrderChangedFromEvent decodes
// AssignmentSortOrderChanged.
func AssignmentSortOrderChangedFromEvent(e store.PersistedEvent) (AssignmentSortOrderChangedPayload, error) {
	if e.StreamType != "assignment" || e.EventType != string(eventtypes.AssignmentSortOrderChanged) {
		return AssignmentSortOrderChangedPayload{}, ErrIgnoredEvent
	}
	out := AssignmentSortOrderChangedPayload{ID: e.StreamID}
	if len(e.Data) == 0 {
		return out, nil
	}
	var raw assignmentSortOrderChangedRaw
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return AssignmentSortOrderChangedPayload{}, fmt.Errorf("projector: invalid AssignmentSortOrderChanged payload: %w", err)
	}
	if raw.SortOrder != nil {
		out.SortOrder = *raw.SortOrder
	}
	return out, nil
}
