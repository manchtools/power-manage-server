package store

import (
	"context"
	"encoding/json"
	"time"
)

// Device is the device projection row. CertFingerprint pins the
// agent cert the device currently uses — used by the
// CertificateHandler to refuse renewals when a different fingerprint
// presents. Labels stays as json.RawMessage at the boundary per the
// JSONB normalize plan in #242.
//
// The compliance-status quadruple (Status / CheckedAt / Total /
// Passing) is denormalized on the device row by the compliance
// projector so the device list/get path doesn't need to join the
// compliance projection per row.
type Device struct {
	ID                  string
	Hostname            string
	AgentVersion        string
	CertFingerprint     *string
	CertNotAfter        *time.Time
	RegisteredAt        *time.Time
	LastSeenAt          *time.Time
	RegistrationTokenID *string
	Labels              json.RawMessage
	IsDeleted           bool
	SyncIntervalMinutes int32
	ComplianceStatus    int32
	ComplianceCheckedAt *time.Time
	ComplianceTotal     int32
	CompliancePassing   int32
}

// DeviceHostname is the narrow (id, hostname) shape returned by the
// bulk-hostname lookup. Used by response builders that need to
// hydrate device names without re-loading the full projection row
// per device.
type DeviceHostname struct {
	ID       string
	Hostname string
}

// GetDeviceKey is the composite key used by the device lookup. The
// optional OwnerScope mirrors the `:self`-scoped permission shape
// used elsewhere: nil = admin view (no scoping), non-nil = restrict
// to devices the user has any assignment to.
type GetDeviceKey struct {
	ID         string
	OwnerScope *string
}

// ListDevicesFilter pairs pagination with the same `:self`-scoped
// owner filter that GetDeviceKey uses.
type ListDevicesFilter struct {
	Limit      int32
	Offset     int32
	OwnerScope *string
}

// DeviceRepo reads device-projection state. Writes flow through
// events (DeviceRegistered / DeviceHeartbeat / DeviceDeleted / etc.)
// and the projector listener.
type DeviceRepo interface {
	// Get returns a device by ID. ownerScope = nil means no
	// scoping; non-nil restricts the lookup to devices the user has
	// assignment access to. Returns ErrNotFound when the device is
	// missing OR when the scope filter excludes it (the handler
	// can't distinguish, by design).
	Get(ctx context.Context, key GetDeviceKey) (Device, error)

	// IsDeleted reports whether the device is soft-deleted. Returns
	// ErrNotFound when the device row never existed.
	IsDeleted(ctx context.Context, id string) (bool, error)

	// List returns a page of devices, optionally scoped to a user
	// via the filter's OwnerScope.
	List(ctx context.Context, filter ListDevicesFilter) ([]Device, error)

	// ListOnline returns a page of devices that have phoned in
	// within the online-window threshold. Pairs with CountOnline
	// for paginated totals.
	ListOnline(ctx context.Context, filter ListDevicesFilter) ([]Device, error)

	// ListOffline returns a page of devices past the online-window
	// threshold. Pairs with CountOffline.
	ListOffline(ctx context.Context, filter ListDevicesFilter) ([]Device, error)

	// Count returns the total non-deleted device count (optionally
	// scoped). Pairs with List.
	Count(ctx context.Context, ownerScope *string) (int64, error)

	// CountOnline / CountOffline mirror their ListXxx counterparts
	// for pagination totals.
	CountOnline(ctx context.Context, ownerScope *string) (int64, error)
	CountOffline(ctx context.Context, ownerScope *string) (int64, error)

	// HostnamesByIDs returns the (id, hostname) pairs for the given
	// device IDs in a single round-trip. Used by response builders
	// in LPS / LUKS / log-query handlers that need to enrich
	// per-device records with hostname.
	HostnamesByIDs(ctx context.Context, ids []string) ([]DeviceHostname, error)

	// SyncInterval returns the per-device sync-interval-minutes
	// configured for offline-scheduler cadence. Returns 0 (the
	// "use default" sentinel) when the device row has no override.
	SyncInterval(ctx context.Context, deviceID string) (int32, error)
}
