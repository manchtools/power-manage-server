package payloads

// Audit-only payloads for the #496 event types. None carries secret or
// result material — they record WHO did WHAT to WHICH device/session, so the
// events table (the audit log) gains the trail these RPCs previously lacked.
// They are intentionally not materialised by any projector.

// OSQueryDispatched records a DispatchOSQuery: an operator ran an osquery
// table read against a device. The table name is the "what"; osquery results
// never appear here.
type OSQueryDispatched struct {
	DeviceID  string `json:"device_id"`
	QueryID   string `json:"query_id"`
	TableName string `json:"table_name"`
}

// DeviceLogsQueried records a QueryDeviceLogs: an operator pulled journald
// logs off a device. The query parameters (unit/priority/window) are the
// "what"; log lines never appear here.
type DeviceLogsQueried struct {
	DeviceID string `json:"device_id"`
	QueryID  string `json:"query_id"`
	Unit     string `json:"unit,omitempty"`
	Priority string `json:"priority,omitempty"`
}

// DeviceInventoryRefreshRequested records a RefreshDeviceInventory dispatch.
type DeviceInventoryRefreshRequested struct {
	DeviceID string `json:"device_id"`
}

// LuksTokenCreated records a CreateLuksToken: an operator issued a one-time
// LUKS key-storage authorization token for a device+action. NO token material
// (not even its hash) is recorded — the audit interest is the grant, not the
// secret.
type LuksTokenCreated struct {
	DeviceID string `json:"device_id"`
	ActionID string `json:"action_id"`
}

// LpsViewedEntry identifies one returned LPS password row — the rotation
// row's ID plus the account it belongs to. Never the password.
type LpsViewedEntry struct {
	RotationID string `json:"rotation_id"`
	Username   string `json:"username"`
	Current    bool   `json:"current"`
}

// LpsPasswordsViewed records a successful GetDeviceLpsPasswords: an operator
// retrieved a device's decrypted LPS passwords (spec 24 / #494). Exactly one
// event per call, listing the returned entries by identifier — the secret
// material never appears here.
type LpsPasswordsViewed struct {
	DeviceID string           `json:"device_id"`
	Entries  []LpsViewedEntry `json:"entries"`
}

// LuksViewedEntry identifies one returned LUKS key row — the rotation row's
// ID plus the encrypted volume it unlocks. Never the passphrase.
type LuksViewedEntry struct {
	RotationID string `json:"rotation_id"`
	DevicePath string `json:"device_path"`
	Current    bool   `json:"current"`
}

// LuksKeysViewed records a successful GetDeviceLuksKeys (spec 24 / #494).
// Exactly one event per call; identifiers only.
type LuksKeysViewed struct {
	DeviceID string            `json:"device_id"`
	Entries  []LuksViewedEntry `json:"entries"`
}

// LpsPasswordsViewDenied records a handler-tier rejection of a
// GetDeviceLpsPasswords (absent device, decrypt failure): who wanted to read
// which device's credentials without getting them. The reason is a fixed
// classification string — no secret material, and the caller-visible
// response (uniform NotFound / Internal) is unchanged by this event.
type LpsPasswordsViewDenied struct {
	DeviceID string `json:"device_id"`
	Reason   string `json:"reason"`
}

// LuksKeysViewDenied is the LUKS counterpart of LpsPasswordsViewDenied.
type LuksKeysViewDenied struct {
	DeviceID string `json:"device_id"`
	Reason   string `json:"reason"`
}

// UserLoggedOut records a Logout: the refresh-token JTI was revoked. The JTI
// is a session identifier, not a credential.
type UserLoggedOut struct {
	JTI string `json:"jti"`
}

// UserSessionRefreshed records a RefreshToken rotation: the old refresh-token
// JTI was revoked and a new session minted. High-frequency by nature; audit
// completeness is the deliberate default (filter the audit view, don't drop
// the event).
type UserSessionRefreshed struct {
	OldJTI string `json:"old_jti,omitempty"`
}
