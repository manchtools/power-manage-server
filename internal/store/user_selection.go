package store

import (
	"context"
	"time"
)

// UserSelection is the per-(device, source) flag tracking which
// users (directly or via groups) should be provisioned on each
// device. Backed by user_selections_projection. SourceType is the
// owning relationship type ("user", "user_group", etc.); SourceID
// is that relationship's ID.
type UserSelection struct {
	ID         string
	DeviceID   string
	SourceType string
	SourceID   string
	Selected   bool
	UpdatedAt  time.Time
	CreatedBy  string
}

// GetUserSelectionKey is the composite key used to look up a single
// user-selection row. The three fields together are unique per row.
type GetUserSelectionKey struct {
	DeviceID   string
	SourceType string
	SourceID   string
}

// UserSelectionRepo reads the per-device user-provisioning selection
// rows. Writes flow through UserSelectionUpdated events; the
// listener owns the upsert into the projection.
type UserSelectionRepo interface {
	// Get returns the selection for a single (device, source) tuple.
	// Returns ErrNotFound when no row exists for that key.
	Get(ctx context.Context, key GetUserSelectionKey) (UserSelection, error)

	// ListForDevice returns every selection row touching the given
	// device, ordered as the projection emits them. Empty slice
	// when the device has no selections yet.
	ListForDevice(ctx context.Context, deviceID string) ([]UserSelection, error)
}
