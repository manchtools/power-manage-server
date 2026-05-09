package payloads

import "encoding/json"

// DeviceRegistered is the wire shape for DeviceRegistered. Pointer
// fields preserve the absent-vs-explicit distinction the listener's
// SQL UPSERT relies on (omitted CertFingerprint => SQL NULL,
// permitted by the column's UNIQUE constraint that allows multiple
// NULLs). CertNotAfter is the RFC 3339 string emitted by the
// registration handler — kept as *string so the wire bytes stay
// byte-identical with the legacy map-literal emission (which used
// time.Format(time.RFC3339), no sub-second precision). The projector
// parses the string back into a time.Time before writing.
type DeviceRegistered struct {
	Hostname            *string         `json:"hostname,omitempty"`
	AgentVersion        *string         `json:"agent_version,omitempty"`
	CertFingerprint     *string         `json:"cert_fingerprint,omitempty"`
	CertNotAfter        *string         `json:"cert_not_after,omitempty"`
	RegistrationTokenID *string         `json:"registration_token_id,omitempty"`
	Labels              json.RawMessage `json:"labels,omitempty"`
	AssignedUserID      *string         `json:"assigned_user_id,omitempty"`
	// CertPEM and CACertPEM are emitted by the registration handler so
	// the response can return signed cert bytes; the projector
	// ignores them. Keeping them here lets the handler pass one typed
	// payload to AppendEvent without dropping back to a map literal.
	CertPEM   *string `json:"cert_pem,omitempty"`
	CACertPEM *string `json:"ca_cert_pem,omitempty"`
}

// DeviceSeen is the wire shape for DeviceSeen.
type DeviceSeen struct {
	AgentVersion *string `json:"agent_version,omitempty"`
	Hostname     *string `json:"hostname,omitempty"`
}

// DeviceHeartbeat is the wire shape for DeviceHeartbeat.
type DeviceHeartbeat struct {
	AgentVersion *string `json:"agent_version,omitempty"`
}

// DeviceCertRenewed is the wire shape for DeviceCertRenewed.
// CertNotAfter is the RFC 3339 string emitted by the renewal handler;
// matches the legacy emit shape and the projector parses back into a
// time.Time before writing.
type DeviceCertRenewed struct {
	CertFingerprint *string `json:"cert_fingerprint,omitempty"`
	CertNotAfter    *string `json:"cert_not_after,omitempty"`
}

// DeviceLabelsUpdated is the wire shape for DeviceLabelsUpdated.
type DeviceLabelsUpdated struct {
	Labels json.RawMessage `json:"labels,omitempty"`
}

// DeviceLabelSet is the wire shape for DeviceLabelSet.
type DeviceLabelSet struct {
	Key   *string `json:"key,omitempty"`
	Value *string `json:"value,omitempty"`
}

// DeviceLabelRemoved is the wire shape for DeviceLabelRemoved.
type DeviceLabelRemoved struct {
	Key *string `json:"key,omitempty"`
}

// DeviceUserAssignment is the wire shape for DeviceAssigned and
// DeviceUnassigned. user_id is required (composite-PK column on the
// projection) but stays a pointer here so the wire encoding matches
// the legacy map[string]any verbatim — the projector validates
// presence on the read side.
type DeviceUserAssignment struct {
	UserID *string `json:"user_id,omitempty"`
}

// DeviceGroupAssignment is the wire shape for DeviceGroupAssigned and
// DeviceGroupUnassigned.
type DeviceGroupAssignment struct {
	GroupID *string `json:"group_id,omitempty"`
}

// DeviceSyncIntervalSet is the wire shape for DeviceSyncIntervalSet.
type DeviceSyncIntervalSet struct {
	SyncIntervalMinutes *int32 `json:"sync_interval_minutes,omitempty"`
}
