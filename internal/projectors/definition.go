package projectors

import (
	"encoding/json"
	"fmt"

	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/store"
)

// defaultDefinitionSchedule mirrors the column default added in
// migration 012 (`{"interval_hours": 8}`) and the PL/pgSQL projector's
// COALESCE fallback for the missing schedule key.
var defaultDefinitionSchedule = []byte(`{"interval_hours": 8}`)

// DefinitionCreatedPayload covers BOTH branches the deleted PL/pgSQL
// projector pair handled:
//
//   - When the payload carries an `action_type` key, project_action_event
//     synthesises an actions_projection row (compliance-policy bootstrap)
//     and project_definition_event no-ops on the definitions_projection
//     side. SynthesisedAction == true.
//   - Otherwise project_definition_event inserts a definitions_projection
//     row and project_action_event no-ops. SynthesisedAction == false.
//
// SynthesisedAction is the dispatch key the listener uses to pick the
// right branch — keeping the routing decision in the decoder lets the
// listener stay branch-shape-symmetric with the other ports.
type DefinitionCreatedPayload struct {
	ID                string
	Name              string
	Description       string
	Schedule          []byte
	CreatedBy         string
	SynthesisedAction bool
	ActionType        int32
	DesiredState      int32
	Params            []byte
	TimeoutSeconds    int32
	ActionDescription *string
}

type definitionCreatedRaw struct {
	Name           string          `json:"name"`
	Description    *string         `json:"description,omitempty"`
	Schedule       json.RawMessage `json:"schedule,omitempty"`
	ActionType     *int32          `json:"action_type,omitempty"`
	DesiredState   *int32          `json:"desired_state,omitempty"`
	Params         json.RawMessage `json:"params,omitempty"`
	TimeoutSeconds *int32          `json:"timeout_seconds,omitempty"`
}

// DefinitionCreatedFromEvent decodes DefinitionCreated for BOTH
// streams (the action stream's synthesised-action branch reuses this
// decoder via the listener dispatch in action_listener.go). The
// SynthesisedAction flag mirrors the PL/pgSQL projector's
// `IF event.data ? 'action_type'` discriminator: presence (not value)
// of the key picks the actions_projection branch; absence picks the
// definitions_projection branch.
//
// The two branches need different field sets:
//   - definitions_projection branch: name, description (defaults to "" —
//     NOT NULL column), schedule (defaults to '{"interval_hours": 8}').
//   - actions_projection synthesis branch: name, description (nullable
//     in actions_projection), action_type, desired_state, params
//     (defaults to '{}'), timeout_seconds (defaults to 300). schedule
//     is intentionally NOT written by the synthesis branch — the
//     PL/pgSQL projector's INSERT into actions_projection on this branch
//     omitted the schedule column entirely, leaving it at the column
//     default (NULL since the actions schedule column is nullable).
func DefinitionCreatedFromEvent(e store.PersistedEvent) (DefinitionCreatedPayload, error) {
	if (e.StreamType != "definition" && e.StreamType != "action") || e.EventType != string(eventtypes.DefinitionCreated) {
		return DefinitionCreatedPayload{}, ErrIgnoredEvent
	}
	if len(e.Data) == 0 {
		return DefinitionCreatedPayload{}, fmt.Errorf("projector: empty DefinitionCreated payload")
	}
	// Discriminate on key presence (not value) using a generic decode —
	// the PL/pgSQL `event.data ? 'action_type'` test treats an explicit
	// JSON null AS present. Mirror that here so a synthesised-action
	// event with `"action_type": null` lands on the synthesis branch.
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(e.Data, &probe); err != nil {
		return DefinitionCreatedPayload{}, fmt.Errorf("projector: invalid DefinitionCreated payload: %w", err)
	}
	_, hasActionType := probe["action_type"]

	var raw definitionCreatedRaw
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return DefinitionCreatedPayload{}, fmt.Errorf("projector: invalid DefinitionCreated payload: %w", err)
	}
	if raw.Name == "" {
		return DefinitionCreatedPayload{}, fmt.Errorf("projector: DefinitionCreated requires name")
	}
	out := DefinitionCreatedPayload{
		ID:                e.StreamID,
		Name:              raw.Name,
		Schedule:          defaultDefinitionSchedule,
		CreatedBy:         e.ActorID,
		SynthesisedAction: hasActionType,
		Params:            defaultActionParams,
		TimeoutSeconds:    defaultActionTimeoutSeconds,
		ActionDescription: raw.Description,
	}
	if raw.Description != nil {
		out.Description = *raw.Description
	}
	if len(raw.Schedule) > 0 {
		out.Schedule = []byte(raw.Schedule)
	}
	if raw.ActionType != nil {
		out.ActionType = *raw.ActionType
	}
	if raw.DesiredState != nil {
		out.DesiredState = *raw.DesiredState
	}
	if len(raw.Params) > 0 {
		out.Params = []byte(raw.Params)
	}
	if raw.TimeoutSeconds != nil {
		out.TimeoutSeconds = *raw.TimeoutSeconds
	}
	return out, nil
}

// DefinitionRenamedPayload — single mutable field. Empty Name is a
// validation error (see ActionRenamed for the same rationale).
type DefinitionRenamedPayload struct {
	ID   string
	Name string
}

type definitionRenamedRaw struct {
	Name string `json:"name"`
}

// DefinitionRenamedFromEvent decodes DefinitionRenamed for BOTH
// streams (action-stream synthesised-action rename + definition-stream
// rename).
func DefinitionRenamedFromEvent(e store.PersistedEvent) (DefinitionRenamedPayload, error) {
	if (e.StreamType != "definition" && e.StreamType != "action") || e.EventType != string(eventtypes.DefinitionRenamed) {
		return DefinitionRenamedPayload{}, ErrIgnoredEvent
	}
	if len(e.Data) == 0 {
		return DefinitionRenamedPayload{}, fmt.Errorf("projector: empty DefinitionRenamed payload")
	}
	var raw definitionRenamedRaw
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return DefinitionRenamedPayload{}, fmt.Errorf("projector: invalid DefinitionRenamed payload: %w", err)
	}
	if raw.Name == "" {
		return DefinitionRenamedPayload{}, fmt.Errorf("projector: DefinitionRenamed requires name")
	}
	return DefinitionRenamedPayload{ID: e.StreamID, Name: raw.Name}, nil
}

// DefinitionDescriptionUpdatedPayload exposes both shapes the
// PL/pgSQL projector pair needed:
//
//   - definitions_projection branch: `COALESCE(payload, "")` — missing
//     key OR explicit empty string both collapse to "" (the column is
//     NOT NULL). Description carries that value.
//   - actions_projection branch (synthesised-action rename — fires when
//     the same DefinitionDescriptionUpdated arrives on the action
//     stream): `event.data->>'description'` direct — absence is NULL,
//     explicit empty is "". DescriptionPtr carries that value (nil on
//     absence, &"" on explicit empty, &"x" on explicit value).
//
// Listener picks DescriptionPtr for the action-stream branch and
// Description for the definition-stream branch so each projection
// keeps its original semantic.
type DefinitionDescriptionUpdatedPayload struct {
	ID             string
	Description    string
	DescriptionPtr *string
}

type definitionDescriptionUpdatedRaw struct {
	Description *string `json:"description,omitempty"`
}

// DefinitionDescriptionUpdatedFromEvent decodes DefinitionDescriptionUpdated
// for BOTH streams (the action stream's synthesised-action branch
// reuses this decoder via the listener dispatch in action_listener.go).
// The decoder accepts both stream types because the PL/pgSQL pair
// shared the event-name with different write semantics.
func DefinitionDescriptionUpdatedFromEvent(e store.PersistedEvent) (DefinitionDescriptionUpdatedPayload, error) {
	if (e.StreamType != "definition" && e.StreamType != "action") || e.EventType != string(eventtypes.DefinitionDescriptionUpdated) {
		return DefinitionDescriptionUpdatedPayload{}, ErrIgnoredEvent
	}
	out := DefinitionDescriptionUpdatedPayload{ID: e.StreamID}
	if len(e.Data) == 0 {
		return out, nil
	}
	var raw definitionDescriptionUpdatedRaw
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return DefinitionDescriptionUpdatedPayload{}, fmt.Errorf("projector: invalid DefinitionDescriptionUpdated payload: %w", err)
	}
	out.DescriptionPtr = raw.Description
	if raw.Description != nil {
		out.Description = *raw.Description
	}
	return out, nil
}

// DefinitionScheduleUpdatedPayload — missing schedule key falls back to
// the column default `{"interval_hours": 8}` (mirrors the PL/pgSQL
// COALESCE against the JSONB default).
type DefinitionScheduleUpdatedPayload struct {
	ID       string
	Schedule []byte
}

type definitionScheduleUpdatedRaw struct {
	Schedule json.RawMessage `json:"schedule,omitempty"`
}

// DefinitionScheduleUpdatedFromEvent decodes DefinitionScheduleUpdated.
func DefinitionScheduleUpdatedFromEvent(e store.PersistedEvent) (DefinitionScheduleUpdatedPayload, error) {
	if e.StreamType != "definition" || e.EventType != string(eventtypes.DefinitionScheduleUpdated) {
		return DefinitionScheduleUpdatedPayload{}, ErrIgnoredEvent
	}
	out := DefinitionScheduleUpdatedPayload{
		ID:       e.StreamID,
		Schedule: defaultDefinitionSchedule,
	}
	if len(e.Data) == 0 {
		return out, nil
	}
	var raw definitionScheduleUpdatedRaw
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return DefinitionScheduleUpdatedPayload{}, fmt.Errorf("projector: invalid DefinitionScheduleUpdated payload: %w", err)
	}
	if len(raw.Schedule) > 0 {
		out.Schedule = []byte(raw.Schedule)
	}
	return out, nil
}

// DefinitionMemberAddedPayload — sort_order defaults to 0 (matches
// PL/pgSQL `COALESCE((payload)::INTEGER, 0)`).
type DefinitionMemberAddedPayload struct {
	DefinitionID string
	ActionSetID  string
	SortOrder    int32
}

type definitionMemberRaw struct {
	ActionSetID string `json:"action_set_id"`
	SortOrder   *int32 `json:"sort_order,omitempty"`
}

// DefinitionMemberAddedFromEvent decodes DefinitionMemberAdded.
func DefinitionMemberAddedFromEvent(e store.PersistedEvent) (DefinitionMemberAddedPayload, error) {
	raw, err := decodePayload[definitionMemberRaw](e, "definition", eventtypes.DefinitionMemberAdded)
	if err != nil {
		return DefinitionMemberAddedPayload{}, err
	}
	if raw.ActionSetID == "" {
		return DefinitionMemberAddedPayload{}, fmt.Errorf("projector: DefinitionMemberAdded requires action_set_id")
	}
	out := DefinitionMemberAddedPayload{DefinitionID: e.StreamID, ActionSetID: raw.ActionSetID}
	if raw.SortOrder != nil {
		out.SortOrder = *raw.SortOrder
	}
	return out, nil
}

// DefinitionMemberRemovedPayload — only action_set_id matters; the
// definition id comes from the stream.
type DefinitionMemberRemovedPayload struct {
	DefinitionID string
	ActionSetID  string
}

type definitionMemberRemovedRaw struct {
	ActionSetID string `json:"action_set_id"`
}

// DefinitionMemberRemovedFromEvent decodes DefinitionMemberRemoved.
func DefinitionMemberRemovedFromEvent(e store.PersistedEvent) (DefinitionMemberRemovedPayload, error) {
	raw, err := decodePayload[definitionMemberRemovedRaw](e, "definition", eventtypes.DefinitionMemberRemoved)
	if err != nil {
		return DefinitionMemberRemovedPayload{}, err
	}
	if raw.ActionSetID == "" {
		return DefinitionMemberRemovedPayload{}, fmt.Errorf("projector: DefinitionMemberRemoved requires action_set_id")
	}
	return DefinitionMemberRemovedPayload{DefinitionID: e.StreamID, ActionSetID: raw.ActionSetID}, nil
}

// DefinitionMemberReorderedPayload — same shape as DefinitionMemberAdded.
type DefinitionMemberReorderedPayload = DefinitionMemberAddedPayload

// DefinitionMemberReorderedFromEvent decodes DefinitionMemberReordered.
func DefinitionMemberReorderedFromEvent(e store.PersistedEvent) (DefinitionMemberReorderedPayload, error) {
	raw, err := decodePayload[definitionMemberRaw](e, "definition", eventtypes.DefinitionMemberReordered)
	if err != nil {
		return DefinitionMemberReorderedPayload{}, err
	}
	if raw.ActionSetID == "" {
		return DefinitionMemberReorderedPayload{}, fmt.Errorf("projector: DefinitionMemberReordered requires action_set_id")
	}
	out := DefinitionMemberReorderedPayload{DefinitionID: e.StreamID, ActionSetID: raw.ActionSetID}
	if raw.SortOrder != nil {
		out.SortOrder = *raw.SortOrder
	}
	return out, nil
}

// DefinitionDeletedFromEvent — payload-less; only validates the
// (stream, event_type) pair. The cascade derives everything from the
// stream id. Accepts both stream types because the action-stream
// invocation soft-deletes the synthesised-action row in
// actions_projection while the definition-stream invocation soft-
// deletes the definitions_projection row.
func DefinitionDeletedFromEvent(e store.PersistedEvent) (string, error) {
	if (e.StreamType != "definition" && e.StreamType != "action") || e.EventType != string(eventtypes.DefinitionDeleted) {
		return "", ErrIgnoredEvent
	}
	return e.StreamID, nil
}
