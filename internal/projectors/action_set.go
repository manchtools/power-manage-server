package projectors

import (
	"encoding/json"
	"fmt"

	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/store"
)

// defaultActionSetSchedule mirrors the column default added in
// migration 012 (`{"interval_hours": 8}`) and the PL/pgSQL projector's
// COALESCE fallback for the missing schedule key. Held as a byte slice
// so the listener can pass it straight to the JSONB column without an
// extra marshal step.
var defaultActionSetSchedule = []byte(`{"interval_hours": 8}`)

// ActionSetCreatedPayload mirrors the fields the deleted PL/pgSQL
// project_action_set_event() read out of an ActionSetCreated event:
//
//   - name (required)
//   - description (defaults to ” to match the PL/pgSQL
//     `COALESCE(payload, ”)` behaviour)
//   - schedule (defaults to '{"interval_hours": 8}' to match the
//     COALESCE fallback against the JSONB column default)
type ActionSetCreatedPayload struct {
	ID          string
	Name        string
	Description string
	Schedule    []byte
	CreatedBy   string
}

type actionSetCreatedRaw struct {
	Name        string          `json:"name"`
	Description *string         `json:"description,omitempty"`
	Schedule    json.RawMessage `json:"schedule,omitempty"`
}

// ActionSetCreatedFromEvent decodes ActionSetCreated. Returns
// ErrIgnoredEvent for any other (stream, event_type) so the listener
// wrapper can silently no-op.
func ActionSetCreatedFromEvent(e store.PersistedEvent) (ActionSetCreatedPayload, error) {
	if e.StreamType != "action_set" || e.EventType != string(eventtypes.ActionSetCreated) {
		return ActionSetCreatedPayload{}, ErrIgnoredEvent
	}
	if len(e.Data) == 0 {
		return ActionSetCreatedPayload{}, fmt.Errorf("projector: empty ActionSetCreated payload")
	}
	var raw actionSetCreatedRaw
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return ActionSetCreatedPayload{}, fmt.Errorf("projector: invalid ActionSetCreated payload: %w", err)
	}
	if raw.Name == "" {
		return ActionSetCreatedPayload{}, fmt.Errorf("projector: ActionSetCreated requires name")
	}
	out := ActionSetCreatedPayload{
		ID:        e.StreamID,
		Name:      raw.Name,
		Schedule:  defaultActionSetSchedule,
		CreatedBy: e.ActorID,
	}
	if raw.Description != nil {
		out.Description = *raw.Description
	}
	if len(raw.Schedule) > 0 {
		// Preserve the wire bytes verbatim so the listener writes the
		// same JSONB the emitter sent (matches the PL/pgSQL projector's
		// `(event.data->'schedule')::JSONB` cast).
		out.Schedule = []byte(raw.Schedule)
	}
	return out, nil
}

// ActionSetRenamedPayload covers the single mutable field the
// PL/pgSQL projector wrote on an ActionSetRenamed event. Empty Name
// is treated as a validation error rather than silently no-op'd —
// the PL/pgSQL projector would have written NULL and broken the
// NOT NULL column constraint, so emitters that drop the field hit
// the same error class either way.
type ActionSetRenamedPayload struct {
	ID   string
	Name string
}

type actionSetRenamedRaw struct {
	Name string `json:"name"`
}

// ActionSetRenamedFromEvent decodes ActionSetRenamed.
func ActionSetRenamedFromEvent(e store.PersistedEvent) (ActionSetRenamedPayload, error) {
	if e.StreamType != "action_set" || e.EventType != string(eventtypes.ActionSetRenamed) {
		return ActionSetRenamedPayload{}, ErrIgnoredEvent
	}
	if len(e.Data) == 0 {
		return ActionSetRenamedPayload{}, fmt.Errorf("projector: empty ActionSetRenamed payload")
	}
	var raw actionSetRenamedRaw
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return ActionSetRenamedPayload{}, fmt.Errorf("projector: invalid ActionSetRenamed payload: %w", err)
	}
	if raw.Name == "" {
		return ActionSetRenamedPayload{}, fmt.Errorf("projector: ActionSetRenamed requires name")
	}
	return ActionSetRenamedPayload{ID: e.StreamID, Name: raw.Name}, nil
}

// ActionSetDescriptionUpdatedPayload mirrors the PL/pgSQL projector's
// `COALESCE(event.data->>'description', ”)` collapse: if the payload
// omits the key OR sends an explicit empty string, the description
// becomes ”. Both cases land here as Description == "".
type ActionSetDescriptionUpdatedPayload struct {
	ID          string
	Description string
}

type actionSetDescriptionUpdatedRaw struct {
	Description *string `json:"description,omitempty"`
}

// ActionSetDescriptionUpdatedFromEvent decodes
// ActionSetDescriptionUpdated. An empty payload (e.g. `{}`) maps to
// Description == "", matching the PL/pgSQL COALESCE-to-empty-string
// behaviour.
func ActionSetDescriptionUpdatedFromEvent(e store.PersistedEvent) (ActionSetDescriptionUpdatedPayload, error) {
	if e.StreamType != "action_set" || e.EventType != string(eventtypes.ActionSetDescriptionUpdated) {
		return ActionSetDescriptionUpdatedPayload{}, ErrIgnoredEvent
	}
	out := ActionSetDescriptionUpdatedPayload{ID: e.StreamID}
	if len(e.Data) == 0 {
		return out, nil
	}
	var raw actionSetDescriptionUpdatedRaw
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return ActionSetDescriptionUpdatedPayload{}, fmt.Errorf("projector: invalid ActionSetDescriptionUpdated payload: %w", err)
	}
	if raw.Description != nil {
		out.Description = *raw.Description
	}
	return out, nil
}

// ActionSetScheduleUpdatedPayload mirrors the projector's
// COALESCE fallback against the JSONB column default. A missing or
// empty schedule key is replaced with `{"interval_hours": 8}`.
type ActionSetScheduleUpdatedPayload struct {
	ID       string
	Schedule []byte
}

type actionSetScheduleUpdatedRaw struct {
	Schedule json.RawMessage `json:"schedule,omitempty"`
}

// ActionSetScheduleUpdatedFromEvent decodes ActionSetScheduleUpdated.
func ActionSetScheduleUpdatedFromEvent(e store.PersistedEvent) (ActionSetScheduleUpdatedPayload, error) {
	if e.StreamType != "action_set" || e.EventType != string(eventtypes.ActionSetScheduleUpdated) {
		return ActionSetScheduleUpdatedPayload{}, ErrIgnoredEvent
	}
	out := ActionSetScheduleUpdatedPayload{
		ID:       e.StreamID,
		Schedule: defaultActionSetSchedule,
	}
	if len(e.Data) == 0 {
		return out, nil
	}
	var raw actionSetScheduleUpdatedRaw
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return ActionSetScheduleUpdatedPayload{}, fmt.Errorf("projector: invalid ActionSetScheduleUpdated payload: %w", err)
	}
	if len(raw.Schedule) > 0 {
		out.Schedule = []byte(raw.Schedule)
	}
	return out, nil
}

// ActionSetMemberAddedPayload mirrors the PL/pgSQL projector's
// per-member fields. Missing sort_order defaults to 0 (matches
// `COALESCE((event.data->>'sort_order')::INTEGER, 0)`).
type ActionSetMemberAddedPayload struct {
	SetID     string
	ActionID  string
	SortOrder int32
}

type actionSetMemberRaw struct {
	ActionID  string `json:"action_id"`
	SortOrder *int32 `json:"sort_order,omitempty"`
}

// ActionSetMemberAddedFromEvent decodes ActionSetMemberAdded.
func ActionSetMemberAddedFromEvent(e store.PersistedEvent) (ActionSetMemberAddedPayload, error) {
	if e.StreamType != "action_set" || e.EventType != string(eventtypes.ActionSetMemberAdded) {
		return ActionSetMemberAddedPayload{}, ErrIgnoredEvent
	}
	if len(e.Data) == 0 {
		return ActionSetMemberAddedPayload{}, fmt.Errorf("projector: empty ActionSetMemberAdded payload")
	}
	var raw actionSetMemberRaw
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return ActionSetMemberAddedPayload{}, fmt.Errorf("projector: invalid ActionSetMemberAdded payload: %w", err)
	}
	if raw.ActionID == "" {
		return ActionSetMemberAddedPayload{}, fmt.Errorf("projector: ActionSetMemberAdded requires action_id")
	}
	out := ActionSetMemberAddedPayload{SetID: e.StreamID, ActionID: raw.ActionID}
	if raw.SortOrder != nil {
		out.SortOrder = *raw.SortOrder
	}
	return out, nil
}

// ActionSetMemberRemovedPayload — only the action_id is needed; the
// set id comes from the stream.
type ActionSetMemberRemovedPayload struct {
	SetID    string
	ActionID string
}

type actionSetMemberRemovedRaw struct {
	ActionID string `json:"action_id"`
}

// ActionSetMemberRemovedFromEvent decodes ActionSetMemberRemoved.
func ActionSetMemberRemovedFromEvent(e store.PersistedEvent) (ActionSetMemberRemovedPayload, error) {
	if e.StreamType != "action_set" || e.EventType != string(eventtypes.ActionSetMemberRemoved) {
		return ActionSetMemberRemovedPayload{}, ErrIgnoredEvent
	}
	if len(e.Data) == 0 {
		return ActionSetMemberRemovedPayload{}, fmt.Errorf("projector: empty ActionSetMemberRemoved payload")
	}
	var raw actionSetMemberRemovedRaw
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return ActionSetMemberRemovedPayload{}, fmt.Errorf("projector: invalid ActionSetMemberRemoved payload: %w", err)
	}
	if raw.ActionID == "" {
		return ActionSetMemberRemovedPayload{}, fmt.Errorf("projector: ActionSetMemberRemoved requires action_id")
	}
	return ActionSetMemberRemovedPayload{SetID: e.StreamID, ActionID: raw.ActionID}, nil
}

// ActionSetMemberReorderedPayload — same shape as the Added payload;
// reuse the underlying decoder.
type ActionSetMemberReorderedPayload = ActionSetMemberAddedPayload

// ActionSetMemberReorderedFromEvent decodes ActionSetMemberReordered.
// Same field set as ActionSetMemberAdded plus the same default-zero
// behaviour for sort_order.
func ActionSetMemberReorderedFromEvent(e store.PersistedEvent) (ActionSetMemberReorderedPayload, error) {
	if e.StreamType != "action_set" || e.EventType != string(eventtypes.ActionSetMemberReordered) {
		return ActionSetMemberReorderedPayload{}, ErrIgnoredEvent
	}
	if len(e.Data) == 0 {
		return ActionSetMemberReorderedPayload{}, fmt.Errorf("projector: empty ActionSetMemberReordered payload")
	}
	var raw actionSetMemberRaw
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return ActionSetMemberReorderedPayload{}, fmt.Errorf("projector: invalid ActionSetMemberReordered payload: %w", err)
	}
	if raw.ActionID == "" {
		return ActionSetMemberReorderedPayload{}, fmt.Errorf("projector: ActionSetMemberReordered requires action_id")
	}
	out := ActionSetMemberReorderedPayload{SetID: e.StreamID, ActionID: raw.ActionID}
	if raw.SortOrder != nil {
		out.SortOrder = *raw.SortOrder
	}
	return out, nil
}
