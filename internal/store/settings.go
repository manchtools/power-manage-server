package store

import (
	"context"
	"time"
)

// ServerSettings is the global, single-row server-settings projection.
// The handler-facing shape drops the implementation-level identity
// (the `id = 'global'` row key) and the projection version — both are
// internal-to-the-store concerns.
type ServerSettings struct {
	UserProvisioningEnabled bool
	SshAccessForAll         bool
	UpdatedAt               time.Time
}

// SettingsRepo reads the global server-settings row.
//
// Writes still go through the event store (ServerSettingUpdated event)
// + projector — there is no Set method here by design.
type SettingsRepo interface {
	// GetServer returns the global server-settings row. Returns
	// ErrNotFound when the projection has not been seeded yet (rare —
	// the row appears on the first ServerSettingUpdated event).
	GetServer(ctx context.Context) (ServerSettings, error)
}
