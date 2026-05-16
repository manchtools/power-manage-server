package store

import (
	"context"
	"time"
)

// LpsPassword is one rotated LPS (Local Privileged Sudo) password
// record for a (device, action, username) triple. Password stays as
// the plaintext that the agent rotated — the projection holds it
// encrypted at the column level via internal/crypto, but the repo
// returns the decrypted value because every caller needs to read
// it. Reduce-blast-radius rule: treat returned values as secret.
type LpsPassword struct {
	ID             string
	DeviceID       string
	ActionID       string
	Username       string
	Password       string
	RotatedAt      time.Time
	RotationReason string
	IsCurrent      bool
	CreatedAt      time.Time
}

// LpsRepo reads LPS-rotation state. Writes happen via the
// LpsPasswordRotated event + projector listener — there is no
// Insert/Update method here by design.
type LpsRepo interface {
	// ListCurrent returns the current (is_current = true) password
	// row per (action, username) on the device — i.e. every account
	// whose latest rotation is still in effect.
	ListCurrent(ctx context.Context, deviceID string) ([]LpsPassword, error)

	// ListHistory returns every recorded rotation for the device,
	// most recent first. Used by the password-history UI.
	ListHistory(ctx context.Context, deviceID string) ([]LpsPassword, error)
}
