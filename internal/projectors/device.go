package projectors

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/manchtools/power-manage/server/internal/store"
)

// defaultDeviceLabels mirrors the PL/pgSQL projector's
// `COALESCE(event.data->'labels', '{}')` fallback for
// DeviceRegistered. Held as raw bytes so the listener can pass it
// straight to the JSONB column without an extra marshal.
var defaultDeviceLabels = []byte(`{}`)

// DeviceRegisteredPayload mirrors the fields the deleted PL/pgSQL
// project_device_event() read out of a DeviceRegistered event:
//
//   - hostname (defaults to "" — matches PL/pgSQL
//     `COALESCE(payload, "")` for the NOT NULL column).
//   - cert_fingerprint (nullable — the UPSERT writes whatever the
//     payload contains. The PL/pgSQL projector wrote NULL when the
//     payload omitted the key, and the column's UNIQUE constraint
//     allows multiple NULLs, so omission is a documented permissive
//     path used by enrollment flows that haven't issued a cert yet.
//     Mirror that here as a *string so omission lands as SQL NULL).
//   - cert_not_after (nullable timestamp).
//   - registration_token_id (nullable).
//   - labels (defaults to `{}` JSONB — matches PL/pgSQL fallback).
//   - assigned_user_id (nullable; when present, the listener cascades
//     to an INSERT into device_assigned_users_projection).
type DeviceRegisteredPayload struct {
	ID                  string
	Hostname            string
	CertFingerprint     *string
	CertNotAfter        *time.Time
	RegistrationTokenID *string
	Labels              []byte
	AssignedUserID      *string
}

type deviceRegisteredRaw struct {
	Hostname            *string         `json:"hostname,omitempty"`
	CertFingerprint     *string         `json:"cert_fingerprint,omitempty"`
	CertNotAfter        *time.Time      `json:"cert_not_after,omitempty"`
	RegistrationTokenID *string         `json:"registration_token_id,omitempty"`
	Labels              json.RawMessage `json:"labels,omitempty"`
	AssignedUserID      *string         `json:"assigned_user_id,omitempty"`
}

// DeviceRegisteredFromEvent decodes DeviceRegistered. Returns
// ErrIgnoredEvent for any other (stream, event_type) so the listener
// wrapper can silently no-op.
func DeviceRegisteredFromEvent(e store.PersistedEvent) (DeviceRegisteredPayload, error) {
	if e.StreamType != "device" || e.EventType != "DeviceRegistered" {
		return DeviceRegisteredPayload{}, ErrIgnoredEvent
	}
	if len(e.Data) == 0 {
		return DeviceRegisteredPayload{}, fmt.Errorf("projector: empty DeviceRegistered payload")
	}
	var raw deviceRegisteredRaw
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return DeviceRegisteredPayload{}, fmt.Errorf("projector: invalid DeviceRegistered payload: %w", err)
	}
	out := DeviceRegisteredPayload{
		ID:                  e.StreamID,
		CertFingerprint:     raw.CertFingerprint,
		CertNotAfter:        raw.CertNotAfter,
		RegistrationTokenID: raw.RegistrationTokenID,
		AssignedUserID:      raw.AssignedUserID,
		Labels:              defaultDeviceLabels,
	}
	if raw.Hostname != nil {
		out.Hostname = *raw.Hostname
	}
	if len(raw.Labels) > 0 {
		// Preserve wire bytes verbatim so the listener writes the same
		// JSONB the emitter sent (matches the PL/pgSQL projector's
		// `event.data->'labels'`).
		out.Labels = []byte(raw.Labels)
	}
	return out, nil
}

// DeviceSeenPayload mirrors the PL/pgSQL projector's COALESCE-on-
// missing semantics for DeviceSeen:
//
//   - agent_version: COALESCE(payload, agent_version) — when missing,
//     the existing column value is preserved. Decoder leaves the
//     pointer nil; the listener uses COALESCE in SQL so we don't need
//     to read the row first.
//   - hostname: COALESCE(NULLIF(payload, ""), hostname) — empty string
//     OR missing key both fall back to the existing value. Decoder
//     leaves nil for missing; explicit empty string also collapses to
//     nil so the SQL COALESCE does the right thing.
type DeviceSeenPayload struct {
	ID           string
	AgentVersion *string
	Hostname     *string
}

type deviceSeenRaw struct {
	AgentVersion *string `json:"agent_version,omitempty"`
	Hostname     *string `json:"hostname,omitempty"`
}

// DeviceSeenFromEvent decodes DeviceSeen. Empty payload is valid (a
// pure heartbeat-style ping that only refreshes last_seen_at).
func DeviceSeenFromEvent(e store.PersistedEvent) (DeviceSeenPayload, error) {
	if e.StreamType != "device" || e.EventType != "DeviceSeen" {
		return DeviceSeenPayload{}, ErrIgnoredEvent
	}
	out := DeviceSeenPayload{ID: e.StreamID}
	if len(e.Data) == 0 {
		return out, nil
	}
	var raw deviceSeenRaw
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return DeviceSeenPayload{}, fmt.Errorf("projector: invalid DeviceSeen payload: %w", err)
	}
	out.AgentVersion = raw.AgentVersion
	// NULLIF(payload, '') collapse: an explicit empty hostname must
	// fall back to the existing column value. Drop the pointer so the
	// SQL COALESCE preserves the prior row state.
	if raw.Hostname != nil && *raw.Hostname == "" {
		out.Hostname = nil
	} else {
		out.Hostname = raw.Hostname
	}
	return out, nil
}

// DeviceHeartbeatPayload mirrors the PL/pgSQL projector's
// COALESCE-on-missing for DeviceHeartbeat: agent_version preserved
// when the payload omits it.
type DeviceHeartbeatPayload struct {
	ID           string
	AgentVersion *string
}

type deviceHeartbeatRaw struct {
	AgentVersion *string `json:"agent_version,omitempty"`
}

// DeviceHeartbeatFromEvent decodes DeviceHeartbeat. Empty payload is
// a valid bare ping.
func DeviceHeartbeatFromEvent(e store.PersistedEvent) (DeviceHeartbeatPayload, error) {
	if e.StreamType != "device" || e.EventType != "DeviceHeartbeat" {
		return DeviceHeartbeatPayload{}, ErrIgnoredEvent
	}
	out := DeviceHeartbeatPayload{ID: e.StreamID}
	if len(e.Data) == 0 {
		return out, nil
	}
	var raw deviceHeartbeatRaw
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return DeviceHeartbeatPayload{}, fmt.Errorf("projector: invalid DeviceHeartbeat payload: %w", err)
	}
	out.AgentVersion = raw.AgentVersion
	return out, nil
}

// DeviceCertRenewedPayload mirrors the PL/pgSQL projector's
// DeviceCertRenewed handling: cert_fingerprint is required,
// cert_not_after is optional (when omitted the existing column value
// is preserved via SQL COALESCE).
type DeviceCertRenewedPayload struct {
	ID              string
	CertFingerprint string
	CertNotAfter    *time.Time
}

type deviceCertRenewedRaw struct {
	CertFingerprint *string    `json:"cert_fingerprint,omitempty"`
	CertNotAfter    *time.Time `json:"cert_not_after,omitempty"`
}

// DeviceCertRenewedFromEvent decodes DeviceCertRenewed.
func DeviceCertRenewedFromEvent(e store.PersistedEvent) (DeviceCertRenewedPayload, error) {
	if e.StreamType != "device" || e.EventType != "DeviceCertRenewed" {
		return DeviceCertRenewedPayload{}, ErrIgnoredEvent
	}
	if len(e.Data) == 0 {
		return DeviceCertRenewedPayload{}, fmt.Errorf("projector: empty DeviceCertRenewed payload")
	}
	var raw deviceCertRenewedRaw
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return DeviceCertRenewedPayload{}, fmt.Errorf("projector: invalid DeviceCertRenewed payload: %w", err)
	}
	if raw.CertFingerprint == nil || *raw.CertFingerprint == "" {
		return DeviceCertRenewedPayload{}, fmt.Errorf("projector: DeviceCertRenewed requires cert_fingerprint")
	}
	return DeviceCertRenewedPayload{
		ID:              e.StreamID,
		CertFingerprint: *raw.CertFingerprint,
		CertNotAfter:    raw.CertNotAfter,
	}, nil
}

// DeviceLabelsUpdatedPayload mirrors the PL/pgSQL projector's
// `COALESCE(event.data->'labels', labels)` for DeviceLabelsUpdated:
// missing key preserves the existing labels JSONB, present key
// REPLACES the entire blob.
type DeviceLabelsUpdatedPayload struct {
	ID     string
	Labels []byte
}

type deviceLabelsUpdatedRaw struct {
	Labels json.RawMessage `json:"labels,omitempty"`
}

// DeviceLabelsUpdatedFromEvent decodes DeviceLabelsUpdated. Empty
// labels => nil byte slice; the SQL COALESCE will preserve the
// existing row value.
func DeviceLabelsUpdatedFromEvent(e store.PersistedEvent) (DeviceLabelsUpdatedPayload, error) {
	if e.StreamType != "device" || e.EventType != "DeviceLabelsUpdated" {
		return DeviceLabelsUpdatedPayload{}, ErrIgnoredEvent
	}
	out := DeviceLabelsUpdatedPayload{ID: e.StreamID}
	if len(e.Data) == 0 {
		return out, nil
	}
	var raw deviceLabelsUpdatedRaw
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return DeviceLabelsUpdatedPayload{}, fmt.Errorf("projector: invalid DeviceLabelsUpdated payload: %w", err)
	}
	if len(raw.Labels) > 0 {
		out.Labels = []byte(raw.Labels)
	}
	return out, nil
}

// DeviceLabelSetPayload mirrors the PL/pgSQL projector's JSONB merge
// for DeviceLabelSet: `labels || jsonb_build_object(key, value)`.
// Both key and value are required strings.
type DeviceLabelSetPayload struct {
	ID    string
	Key   string
	Value string
}

type deviceLabelSetRaw struct {
	Key   *string `json:"key,omitempty"`
	Value *string `json:"value,omitempty"`
}

// DeviceLabelSetFromEvent decodes DeviceLabelSet.
func DeviceLabelSetFromEvent(e store.PersistedEvent) (DeviceLabelSetPayload, error) {
	if e.StreamType != "device" || e.EventType != "DeviceLabelSet" {
		return DeviceLabelSetPayload{}, ErrIgnoredEvent
	}
	if len(e.Data) == 0 {
		return DeviceLabelSetPayload{}, fmt.Errorf("projector: empty DeviceLabelSet payload")
	}
	var raw deviceLabelSetRaw
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return DeviceLabelSetPayload{}, fmt.Errorf("projector: invalid DeviceLabelSet payload: %w", err)
	}
	if raw.Key == nil || *raw.Key == "" {
		return DeviceLabelSetPayload{}, fmt.Errorf("projector: DeviceLabelSet requires key")
	}
	out := DeviceLabelSetPayload{ID: e.StreamID, Key: *raw.Key}
	if raw.Value != nil {
		out.Value = *raw.Value
	}
	return out, nil
}

// DeviceLabelRemovedPayload mirrors the PL/pgSQL projector's
// `labels - (event.data->>'key')` for DeviceLabelRemoved.
type DeviceLabelRemovedPayload struct {
	ID  string
	Key string
}

type deviceLabelRemovedRaw struct {
	Key *string `json:"key,omitempty"`
}

// DeviceLabelRemovedFromEvent decodes DeviceLabelRemoved.
func DeviceLabelRemovedFromEvent(e store.PersistedEvent) (DeviceLabelRemovedPayload, error) {
	if e.StreamType != "device" || e.EventType != "DeviceLabelRemoved" {
		return DeviceLabelRemovedPayload{}, ErrIgnoredEvent
	}
	if len(e.Data) == 0 {
		return DeviceLabelRemovedPayload{}, fmt.Errorf("projector: empty DeviceLabelRemoved payload")
	}
	var raw deviceLabelRemovedRaw
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return DeviceLabelRemovedPayload{}, fmt.Errorf("projector: invalid DeviceLabelRemoved payload: %w", err)
	}
	if raw.Key == nil || *raw.Key == "" {
		return DeviceLabelRemovedPayload{}, fmt.Errorf("projector: DeviceLabelRemoved requires key")
	}
	return DeviceLabelRemovedPayload{ID: e.StreamID, Key: *raw.Key}, nil
}

// DeviceUserAssignmentPayload covers DeviceAssigned and
// DeviceUnassigned. user_id is required because the underlying
// composite PK column would otherwise be NULL — surfacing as a
// Postgres constraint violation under the PL/pgSQL projector. We
// surface the missing-field case as a decoder validation error so
// the listener log makes the failure obvious.
type DeviceUserAssignmentPayload struct {
	DeviceID string
	UserID   string
}

type deviceUserAssignmentRaw struct {
	UserID *string `json:"user_id,omitempty"`
}

// DeviceAssignedFromEvent decodes DeviceAssigned.
func DeviceAssignedFromEvent(e store.PersistedEvent) (DeviceUserAssignmentPayload, error) {
	if e.StreamType != "device" || e.EventType != "DeviceAssigned" {
		return DeviceUserAssignmentPayload{}, ErrIgnoredEvent
	}
	return decodeDeviceUserAssignment(e)
}

// DeviceUnassignedFromEvent decodes DeviceUnassigned.
func DeviceUnassignedFromEvent(e store.PersistedEvent) (DeviceUserAssignmentPayload, error) {
	if e.StreamType != "device" || e.EventType != "DeviceUnassigned" {
		return DeviceUserAssignmentPayload{}, ErrIgnoredEvent
	}
	return decodeDeviceUserAssignment(e)
}

func decodeDeviceUserAssignment(e store.PersistedEvent) (DeviceUserAssignmentPayload, error) {
	if len(e.Data) == 0 {
		return DeviceUserAssignmentPayload{}, fmt.Errorf("projector: empty %s payload", e.EventType)
	}
	var raw deviceUserAssignmentRaw
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return DeviceUserAssignmentPayload{}, fmt.Errorf("projector: invalid %s payload: %w", e.EventType, err)
	}
	if raw.UserID == nil || *raw.UserID == "" {
		return DeviceUserAssignmentPayload{}, fmt.Errorf("projector: %s requires user_id", e.EventType)
	}
	return DeviceUserAssignmentPayload{DeviceID: e.StreamID, UserID: *raw.UserID}, nil
}

// DeviceGroupAssignmentPayload covers DeviceGroupAssigned and
// DeviceGroupUnassigned. group_id is required for the same reason
// user_id is on DeviceAssigned: composite-PK column.
type DeviceGroupAssignmentPayload struct {
	DeviceID string
	GroupID  string
}

type deviceGroupAssignmentRaw struct {
	GroupID *string `json:"group_id,omitempty"`
}

// DeviceGroupAssignedFromEvent decodes DeviceGroupAssigned.
func DeviceGroupAssignedFromEvent(e store.PersistedEvent) (DeviceGroupAssignmentPayload, error) {
	if e.StreamType != "device" || e.EventType != "DeviceGroupAssigned" {
		return DeviceGroupAssignmentPayload{}, ErrIgnoredEvent
	}
	return decodeDeviceGroupAssignment(e)
}

// DeviceGroupUnassignedFromEvent decodes DeviceGroupUnassigned.
func DeviceGroupUnassignedFromEvent(e store.PersistedEvent) (DeviceGroupAssignmentPayload, error) {
	if e.StreamType != "device" || e.EventType != "DeviceGroupUnassigned" {
		return DeviceGroupAssignmentPayload{}, ErrIgnoredEvent
	}
	return decodeDeviceGroupAssignment(e)
}

func decodeDeviceGroupAssignment(e store.PersistedEvent) (DeviceGroupAssignmentPayload, error) {
	if len(e.Data) == 0 {
		return DeviceGroupAssignmentPayload{}, fmt.Errorf("projector: empty %s payload", e.EventType)
	}
	var raw deviceGroupAssignmentRaw
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return DeviceGroupAssignmentPayload{}, fmt.Errorf("projector: invalid %s payload: %w", e.EventType, err)
	}
	if raw.GroupID == nil || *raw.GroupID == "" {
		return DeviceGroupAssignmentPayload{}, fmt.Errorf("projector: %s requires group_id", e.EventType)
	}
	return DeviceGroupAssignmentPayload{DeviceID: e.StreamID, GroupID: *raw.GroupID}, nil
}

// DeviceSyncIntervalSetPayload mirrors the PL/pgSQL projector's
// `COALESCE((event.data->>'sync_interval_minutes')::INTEGER, 0)`:
// missing key collapses to 0.
type DeviceSyncIntervalSetPayload struct {
	ID                  string
	SyncIntervalMinutes int32
}

type deviceSyncIntervalSetRaw struct {
	SyncIntervalMinutes *int32 `json:"sync_interval_minutes,omitempty"`
}

// DeviceSyncIntervalSetFromEvent decodes DeviceSyncIntervalSet.
func DeviceSyncIntervalSetFromEvent(e store.PersistedEvent) (DeviceSyncIntervalSetPayload, error) {
	if e.StreamType != "device" || e.EventType != "DeviceSyncIntervalSet" {
		return DeviceSyncIntervalSetPayload{}, ErrIgnoredEvent
	}
	out := DeviceSyncIntervalSetPayload{ID: e.StreamID}
	if len(e.Data) == 0 {
		return out, nil
	}
	var raw deviceSyncIntervalSetRaw
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return DeviceSyncIntervalSetPayload{}, fmt.Errorf("projector: invalid DeviceSyncIntervalSet payload: %w", err)
	}
	if raw.SyncIntervalMinutes != nil {
		out.SyncIntervalMinutes = *raw.SyncIntervalMinutes
	}
	return out, nil
}
