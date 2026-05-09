package projectors

import (
	"encoding/json"
	"fmt"

	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/store"
)

// CompliancePolicyCreatedPayload mirrors the fields the deleted PL/pgSQL
// project_compliance_policy_event() read out of a CompliancePolicyCreated
// event:
//
//   - name (required, NOT NULL column — the PL/pgSQL projector wrote
//     `event.data->>'name'` directly into the column; missing key would
//     surface as a constraint violation, so we surface that as a
//     decoder-level validation error one layer earlier).
//   - description (defaults to "" to match the PL/pgSQL
//     `COALESCE(event.data->>'description', "")` fallback).
type CompliancePolicyCreatedPayload struct {
	ID          string
	Name        string
	Description string
	CreatedBy   string
}

type compliancePolicyCreatedRaw struct {
	Name        string  `json:"name"`
	Description *string `json:"description,omitempty"`
}

// CompliancePolicyCreatedFromEvent decodes CompliancePolicyCreated.
// Returns ErrIgnoredEvent for any other (stream, event_type) so the
// listener wrapper can silently no-op.
func CompliancePolicyCreatedFromEvent(e store.PersistedEvent) (CompliancePolicyCreatedPayload, error) {
	if e.StreamType != "compliance_policy" || e.EventType != string(eventtypes.CompliancePolicyCreated) {
		return CompliancePolicyCreatedPayload{}, ErrIgnoredEvent
	}
	if len(e.Data) == 0 {
		return CompliancePolicyCreatedPayload{}, fmt.Errorf("projector: empty CompliancePolicyCreated payload")
	}
	var raw compliancePolicyCreatedRaw
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return CompliancePolicyCreatedPayload{}, fmt.Errorf("projector: invalid CompliancePolicyCreated payload: %w", err)
	}
	if raw.Name == "" {
		return CompliancePolicyCreatedPayload{}, fmt.Errorf("projector: CompliancePolicyCreated requires name")
	}
	out := CompliancePolicyCreatedPayload{
		ID:        e.StreamID,
		Name:      raw.Name,
		CreatedBy: e.ActorID,
	}
	if raw.Description != nil {
		out.Description = *raw.Description
	}
	return out, nil
}

// CompliancePolicyRenamedPayload mirrors the fields the PL/pgSQL
// projector read for a CompliancePolicyRenamed event. Name is required
// — the PL/pgSQL projector assigned `event.data->>'name'` directly into
// the NOT NULL column, so a missing key would have nulled it out.
type CompliancePolicyRenamedPayload struct {
	ID   string
	Name string
}

type compliancePolicyRenamedRaw struct {
	Name string `json:"name"`
}

// CompliancePolicyRenamedFromEvent decodes CompliancePolicyRenamed.
func CompliancePolicyRenamedFromEvent(e store.PersistedEvent) (CompliancePolicyRenamedPayload, error) {
	if e.StreamType != "compliance_policy" || e.EventType != string(eventtypes.CompliancePolicyRenamed) {
		return CompliancePolicyRenamedPayload{}, ErrIgnoredEvent
	}
	if len(e.Data) == 0 {
		return CompliancePolicyRenamedPayload{}, fmt.Errorf("projector: empty CompliancePolicyRenamed payload")
	}
	var raw compliancePolicyRenamedRaw
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return CompliancePolicyRenamedPayload{}, fmt.Errorf("projector: invalid CompliancePolicyRenamed payload: %w", err)
	}
	if raw.Name == "" {
		return CompliancePolicyRenamedPayload{}, fmt.Errorf("projector: CompliancePolicyRenamed requires name")
	}
	return CompliancePolicyRenamedPayload{ID: e.StreamID, Name: raw.Name}, nil
}

// CompliancePolicyDescriptionUpdatedPayload mirrors the PL/pgSQL
// projector's `COALESCE(event.data->>'description', "")` fallback —
// missing or null description collapses to the empty string so the
// underlying NOT NULL column gets a valid value.
type CompliancePolicyDescriptionUpdatedPayload struct {
	ID          string
	Description string
}

type compliancePolicyDescriptionUpdatedRaw struct {
	Description *string `json:"description,omitempty"`
}

// CompliancePolicyDescriptionUpdatedFromEvent decodes
// CompliancePolicyDescriptionUpdated.
func CompliancePolicyDescriptionUpdatedFromEvent(e store.PersistedEvent) (CompliancePolicyDescriptionUpdatedPayload, error) {
	if e.StreamType != "compliance_policy" || e.EventType != string(eventtypes.CompliancePolicyDescriptionUpdated) {
		return CompliancePolicyDescriptionUpdatedPayload{}, ErrIgnoredEvent
	}
	out := CompliancePolicyDescriptionUpdatedPayload{ID: e.StreamID}
	if len(e.Data) == 0 {
		return out, nil
	}
	var raw compliancePolicyDescriptionUpdatedRaw
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return CompliancePolicyDescriptionUpdatedPayload{}, fmt.Errorf("projector: invalid CompliancePolicyDescriptionUpdated payload: %w", err)
	}
	if raw.Description != nil {
		out.Description = *raw.Description
	}
	return out, nil
}

// CompliancePolicyRuleAddedPayload mirrors the PL/pgSQL projector's
// reads for a CompliancePolicyRuleAdded event:
//
//   - action_id (required, composite-PK column).
//   - action_name (defaults to "" — matches PL/pgSQL
//     `COALESCE(event.data->>'action_name', "")` for the NOT NULL column).
//   - grace_period_hours (defaults to 0 — matches PL/pgSQL
//     `COALESCE((event.data->>'grace_period_hours')::INTEGER, 0)`).
//
// PolicyID is sourced from the event's stream_id (the PL/pgSQL projector
// indexed off `event.stream_id`), not the payload.
type CompliancePolicyRuleAddedPayload struct {
	PolicyID         string
	ActionID         string
	ActionName       string
	GracePeriodHours int32
}

type compliancePolicyRuleAddedRaw struct {
	ActionID         string  `json:"action_id"`
	ActionName       *string `json:"action_name,omitempty"`
	GracePeriodHours *int32  `json:"grace_period_hours,omitempty"`
}

// CompliancePolicyRuleAddedFromEvent decodes CompliancePolicyRuleAdded.
func CompliancePolicyRuleAddedFromEvent(e store.PersistedEvent) (CompliancePolicyRuleAddedPayload, error) {
	if e.StreamType != "compliance_policy" || e.EventType != string(eventtypes.CompliancePolicyRuleAdded) {
		return CompliancePolicyRuleAddedPayload{}, ErrIgnoredEvent
	}
	if len(e.Data) == 0 {
		return CompliancePolicyRuleAddedPayload{}, fmt.Errorf("projector: empty CompliancePolicyRuleAdded payload")
	}
	var raw compliancePolicyRuleAddedRaw
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return CompliancePolicyRuleAddedPayload{}, fmt.Errorf("projector: invalid CompliancePolicyRuleAdded payload: %w", err)
	}
	if raw.ActionID == "" {
		return CompliancePolicyRuleAddedPayload{}, fmt.Errorf("projector: CompliancePolicyRuleAdded requires action_id")
	}
	out := CompliancePolicyRuleAddedPayload{
		PolicyID: e.StreamID,
		ActionID: raw.ActionID,
	}
	if raw.ActionName != nil {
		out.ActionName = *raw.ActionName
	}
	if raw.GracePeriodHours != nil {
		out.GracePeriodHours = *raw.GracePeriodHours
	}
	return out, nil
}

// CompliancePolicyRuleRemovedPayload covers CompliancePolicyRuleRemoved.
// Only action_id is read from the payload; PolicyID comes from the
// stream id (matches the PL/pgSQL projector's `event.stream_id`).
type CompliancePolicyRuleRemovedPayload struct {
	PolicyID string
	ActionID string
}

type compliancePolicyRuleRemovedRaw struct {
	ActionID string `json:"action_id"`
}

// CompliancePolicyRuleRemovedFromEvent decodes CompliancePolicyRuleRemoved.
func CompliancePolicyRuleRemovedFromEvent(e store.PersistedEvent) (CompliancePolicyRuleRemovedPayload, error) {
	if e.StreamType != "compliance_policy" || e.EventType != string(eventtypes.CompliancePolicyRuleRemoved) {
		return CompliancePolicyRuleRemovedPayload{}, ErrIgnoredEvent
	}
	if len(e.Data) == 0 {
		return CompliancePolicyRuleRemovedPayload{}, fmt.Errorf("projector: empty CompliancePolicyRuleRemoved payload")
	}
	var raw compliancePolicyRuleRemovedRaw
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return CompliancePolicyRuleRemovedPayload{}, fmt.Errorf("projector: invalid CompliancePolicyRuleRemoved payload: %w", err)
	}
	if raw.ActionID == "" {
		return CompliancePolicyRuleRemovedPayload{}, fmt.Errorf("projector: CompliancePolicyRuleRemoved requires action_id")
	}
	return CompliancePolicyRuleRemovedPayload{
		PolicyID: e.StreamID,
		ActionID: raw.ActionID,
	}, nil
}

// CompliancePolicyRuleUpdatedPayload mirrors the PL/pgSQL projector's
// reads for a CompliancePolicyRuleUpdated event:
//
//   - action_id (required, composite-PK column the UPDATE filters on).
//   - grace_period_hours (defaults to 0 — matches PL/pgSQL
//     `COALESCE((event.data->>'grace_period_hours')::INTEGER, 0)`).
type CompliancePolicyRuleUpdatedPayload struct {
	PolicyID         string
	ActionID         string
	GracePeriodHours int32
}

type compliancePolicyRuleUpdatedRaw struct {
	ActionID         string `json:"action_id"`
	GracePeriodHours *int32 `json:"grace_period_hours,omitempty"`
}

// CompliancePolicyRuleUpdatedFromEvent decodes CompliancePolicyRuleUpdated.
func CompliancePolicyRuleUpdatedFromEvent(e store.PersistedEvent) (CompliancePolicyRuleUpdatedPayload, error) {
	if e.StreamType != "compliance_policy" || e.EventType != string(eventtypes.CompliancePolicyRuleUpdated) {
		return CompliancePolicyRuleUpdatedPayload{}, ErrIgnoredEvent
	}
	if len(e.Data) == 0 {
		return CompliancePolicyRuleUpdatedPayload{}, fmt.Errorf("projector: empty CompliancePolicyRuleUpdated payload")
	}
	var raw compliancePolicyRuleUpdatedRaw
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return CompliancePolicyRuleUpdatedPayload{}, fmt.Errorf("projector: invalid CompliancePolicyRuleUpdated payload: %w", err)
	}
	if raw.ActionID == "" {
		return CompliancePolicyRuleUpdatedPayload{}, fmt.Errorf("projector: CompliancePolicyRuleUpdated requires action_id")
	}
	out := CompliancePolicyRuleUpdatedPayload{
		PolicyID: e.StreamID,
		ActionID: raw.ActionID,
	}
	if raw.GracePeriodHours != nil {
		out.GracePeriodHours = *raw.GracePeriodHours
	}
	return out, nil
}
