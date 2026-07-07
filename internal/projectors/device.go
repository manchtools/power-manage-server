package projectors

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/eventtypes/payloads"
	"github.com/manchtools/power-manage/server/internal/store"
)

// decodeLabelsMap accepts the JSONB-encoded {key:value} bytes the
// emitter put on the wire and returns the parallel map[string]string
// the device_labels child table consumes. Returns nil on empty input
// or a non-object payload so the listener can skip the child-write
// path cleanly. Non-string values are coerced via fmt.Sprint to match
// the PL/pgSQL `->>` coercion that always returned TEXT.
func decodeLabelsMap(raw []byte) map[string]string {
	if len(raw) == 0 {
		return nil
	}
	var any map[string]any
	if err := json.Unmarshal(raw, &any); err != nil || len(any) == 0 {
		return nil
	}
	out := make(map[string]string, len(any))
	for k, v := range any {
		switch x := v.(type) {
		case string:
			out[k] = x
		case nil:
			out[k] = ""
		default:
			out[k] = fmt.Sprint(x)
		}
	}
	return out
}

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
	Labels              map[string]string
	AssignedUserID      *string
}

// DeviceRegisteredFromEvent decodes DeviceRegistered. Returns
// ErrIgnoredEvent for any other (stream, event_type) so the listener
// wrapper can silently no-op.
func DeviceRegisteredFromEvent(e store.PersistedEvent) (DeviceRegisteredPayload, error) {
	raw, err := decodePayload[payloads.DeviceRegistered](e, "device", eventtypes.DeviceRegistered)
	if err != nil {
		return DeviceRegisteredPayload{}, err
	}
	out := DeviceRegisteredPayload{
		ID:                  e.StreamID,
		CertFingerprint:     raw.CertFingerprint,
		RegistrationTokenID: raw.RegistrationTokenID,
		AssignedUserID:      raw.AssignedUserID,
	}
	notAfter, err := parseOptionalRFC3339(raw.CertNotAfter)
	if err != nil {
		return DeviceRegisteredPayload{}, fmt.Errorf("projector: invalid cert_not_after on DeviceRegistered: %w", err)
	}
	out.CertNotAfter = notAfter
	if raw.Hostname != nil {
		out.Hostname = *raw.Hostname
	}
	out.Labels = decodeLabelsMap(raw.Labels)
	return out, nil
}

// parseOptionalRFC3339 parses an RFC 3339 (or RFC 3339Nano) timestamp
// string into a *time.Time, treating nil and empty as "absent" (returns
// nil with no error). Centralised here because every cert-related
// payload that emits as a string-formatted timestamp needs the same
// dual-format tolerant parse on the way back into a column.
func parseOptionalRFC3339(s *string) (*time.Time, error) {
	if s == nil || *s == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339, *s)
	if err != nil {
		// Fall back to RFC 3339Nano so an emitter that switches
		// formatters in the future doesn't silently corrupt
		// downstream time arithmetic.
		t, err = time.Parse(time.RFC3339Nano, *s)
		if err != nil {
			return nil, err
		}
	}
	return &t, nil
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

// DeviceSeenFromEvent decodes DeviceSeen. Empty payload is valid (a
// pure heartbeat-style ping that only refreshes last_seen_at).
func DeviceSeenFromEvent(e store.PersistedEvent) (DeviceSeenPayload, error) {
	if e.StreamType != "device" || e.EventType != string(eventtypes.DeviceSeen) {
		return DeviceSeenPayload{}, ErrIgnoredEvent
	}
	out := DeviceSeenPayload{ID: e.StreamID}
	if len(e.Data) == 0 {
		return out, nil
	}
	var raw payloads.DeviceSeen
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

// DeviceHeartbeatFromEvent decodes DeviceHeartbeat. Empty payload is
// a valid bare ping.
func DeviceHeartbeatFromEvent(e store.PersistedEvent) (DeviceHeartbeatPayload, error) {
	if e.StreamType != "device" || e.EventType != string(eventtypes.DeviceHeartbeat) {
		return DeviceHeartbeatPayload{}, ErrIgnoredEvent
	}
	out := DeviceHeartbeatPayload{ID: e.StreamID}
	if len(e.Data) == 0 {
		return out, nil
	}
	var raw payloads.DeviceHeartbeat
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

// DeviceCertRenewedFromEvent decodes DeviceCertRenewed.
func DeviceCertRenewedFromEvent(e store.PersistedEvent) (DeviceCertRenewedPayload, error) {
	raw, err := decodePayload[payloads.DeviceCertRenewed](e, "device", eventtypes.DeviceCertRenewed)
	if err != nil {
		return DeviceCertRenewedPayload{}, err
	}
	if raw.CertFingerprint == nil || *raw.CertFingerprint == "" {
		return DeviceCertRenewedPayload{}, fmt.Errorf("projector: DeviceCertRenewed requires cert_fingerprint")
	}
	notAfter, err := parseOptionalRFC3339(raw.CertNotAfter)
	if err != nil {
		return DeviceCertRenewedPayload{}, fmt.Errorf("projector: invalid cert_not_after on DeviceCertRenewed: %w", err)
	}
	return DeviceCertRenewedPayload{
		ID:              e.StreamID,
		CertFingerprint: *raw.CertFingerprint,
		CertNotAfter:    notAfter,
	}, nil
}

// DeviceLabelsUpdatedPayload carries the new label set for
// DeviceLabelsUpdated. The listener clears the existing device_labels
// rows for the device and inserts every (key, value) here in one
// transaction — matches the PL/pgSQL projector's "REPLACE the entire
// JSONB blob" semantics. HasLabels distinguishes "labels key was
// missing on the wire — preserve" from "labels key was present and
// empty — clear all".
type DeviceLabelsUpdatedPayload struct {
	ID        string
	Labels    map[string]string
	HasLabels bool
}

// DeviceLabelsUpdatedFromEvent decodes DeviceLabelsUpdated. Absent
// labels key on the wire => HasLabels=false; the listener will skip the
// child-table writes (preserves the existing rows). Present labels =>
// HasLabels=true and Labels carries the new set (possibly empty, which
// means clear all).
func DeviceLabelsUpdatedFromEvent(e store.PersistedEvent) (DeviceLabelsUpdatedPayload, error) {
	if e.StreamType != "device" || e.EventType != string(eventtypes.DeviceLabelsUpdated) {
		return DeviceLabelsUpdatedPayload{}, ErrIgnoredEvent
	}
	out := DeviceLabelsUpdatedPayload{ID: e.StreamID}
	if len(e.Data) == 0 {
		return out, nil
	}
	var raw payloads.DeviceLabelsUpdated
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return DeviceLabelsUpdatedPayload{}, fmt.Errorf("projector: invalid DeviceLabelsUpdated payload: %w", err)
	}
	if len(raw.Labels) > 0 {
		out.Labels = decodeLabelsMap(raw.Labels)
		out.HasLabels = true
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

// DeviceLabelSetFromEvent decodes DeviceLabelSet.
func DeviceLabelSetFromEvent(e store.PersistedEvent) (DeviceLabelSetPayload, error) {
	raw, err := decodePayload[payloads.DeviceLabelSet](e, "device", eventtypes.DeviceLabelSet)
	if err != nil {
		return DeviceLabelSetPayload{}, err
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

// DeviceLabelRemovedFromEvent decodes DeviceLabelRemoved.
func DeviceLabelRemovedFromEvent(e store.PersistedEvent) (DeviceLabelRemovedPayload, error) {
	raw, err := decodePayload[payloads.DeviceLabelRemoved](e, "device", eventtypes.DeviceLabelRemoved)
	if err != nil {
		return DeviceLabelRemovedPayload{}, err
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

// DeviceAssignedFromEvent decodes DeviceAssigned.
func DeviceAssignedFromEvent(e store.PersistedEvent) (DeviceUserAssignmentPayload, error) {
	if e.StreamType != "device" || e.EventType != string(eventtypes.DeviceAssigned) {
		return DeviceUserAssignmentPayload{}, ErrIgnoredEvent
	}
	return decodeDeviceUserAssignment(e)
}

// DeviceUnassignedFromEvent decodes DeviceUnassigned.
func DeviceUnassignedFromEvent(e store.PersistedEvent) (DeviceUserAssignmentPayload, error) {
	if e.StreamType != "device" || e.EventType != string(eventtypes.DeviceUnassigned) {
		return DeviceUserAssignmentPayload{}, ErrIgnoredEvent
	}
	return decodeDeviceUserAssignment(e)
}

func decodeDeviceUserAssignment(e store.PersistedEvent) (DeviceUserAssignmentPayload, error) {
	if len(e.Data) == 0 {
		return DeviceUserAssignmentPayload{}, fmt.Errorf("projector: empty %s payload", e.EventType)
	}
	var raw payloads.DeviceUserAssignment
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

// DeviceGroupAssignedFromEvent decodes DeviceGroupAssigned.
func DeviceGroupAssignedFromEvent(e store.PersistedEvent) (DeviceGroupAssignmentPayload, error) {
	if e.StreamType != "device" || e.EventType != string(eventtypes.DeviceGroupAssigned) {
		return DeviceGroupAssignmentPayload{}, ErrIgnoredEvent
	}
	return decodeDeviceGroupAssignment(e)
}

// DeviceGroupUnassignedFromEvent decodes DeviceGroupUnassigned.
func DeviceGroupUnassignedFromEvent(e store.PersistedEvent) (DeviceGroupAssignmentPayload, error) {
	if e.StreamType != "device" || e.EventType != string(eventtypes.DeviceGroupUnassigned) {
		return DeviceGroupAssignmentPayload{}, ErrIgnoredEvent
	}
	return decodeDeviceGroupAssignment(e)
}

func decodeDeviceGroupAssignment(e store.PersistedEvent) (DeviceGroupAssignmentPayload, error) {
	if len(e.Data) == 0 {
		return DeviceGroupAssignmentPayload{}, fmt.Errorf("projector: empty %s payload", e.EventType)
	}
	var raw payloads.DeviceGroupAssignment
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

// DeviceSyncIntervalSetFromEvent decodes DeviceSyncIntervalSet.
func DeviceSyncIntervalSetFromEvent(e store.PersistedEvent) (DeviceSyncIntervalSetPayload, error) {
	if e.StreamType != "device" || e.EventType != string(eventtypes.DeviceSyncIntervalSet) {
		return DeviceSyncIntervalSetPayload{}, ErrIgnoredEvent
	}
	out := DeviceSyncIntervalSetPayload{ID: e.StreamID}
	if len(e.Data) == 0 {
		return out, nil
	}
	var raw payloads.DeviceSyncIntervalSet
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return DeviceSyncIntervalSetPayload{}, fmt.Errorf("projector: invalid DeviceSyncIntervalSet payload: %w", err)
	}
	if raw.SyncIntervalMinutes != nil {
		out.SyncIntervalMinutes = *raw.SyncIntervalMinutes
	}
	return out, nil
}

// DeviceInventoryIntervalSetPayload is the decoded per-device inventory
// interval override (spec 22). A missing key collapses to 0 ("inherit"),
// matching the sync-interval decoder's COALESCE semantics.
type DeviceInventoryIntervalSetPayload struct {
	ID                       string
	InventoryIntervalMinutes int32
}

// DeviceInventoryIntervalSetFromEvent decodes DeviceInventoryIntervalSet.
func DeviceInventoryIntervalSetFromEvent(e store.PersistedEvent) (DeviceInventoryIntervalSetPayload, error) {
	if e.StreamType != "device" || e.EventType != string(eventtypes.DeviceInventoryIntervalSet) {
		return DeviceInventoryIntervalSetPayload{}, ErrIgnoredEvent
	}
	out := DeviceInventoryIntervalSetPayload{ID: e.StreamID}
	if len(e.Data) == 0 {
		return out, nil
	}
	var raw payloads.DeviceInventoryIntervalSet
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return DeviceInventoryIntervalSetPayload{}, fmt.Errorf("projector: invalid DeviceInventoryIntervalSet payload: %w", err)
	}
	if raw.InventoryIntervalMinutes != nil {
		out.InventoryIntervalMinutes = *raw.InventoryIntervalMinutes
	}
	return out, nil
}
