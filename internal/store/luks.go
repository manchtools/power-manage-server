package store

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// LuksKey is one rotated LUKS passphrase record for a (device,
// action) pair. Passphrase is the decrypted secret — same blast-
// radius rule as LPS: treat values as sensitive in callers.
type LuksKey struct {
	ID               uuid.UUID
	DeviceID         string
	ActionID         string
	DevicePath       string
	Passphrase       string
	RotatedAt        time.Time
	RotationReason   string
	IsCurrent        bool
	CreatedAt        time.Time
	RevocationStatus *string
	RevocationError  *string
	RevocationAt     *time.Time
}

// LuksToken is one short-lived one-time token a device must present
// when retrieving the current LUKS key. Tokens carry the minimum
// password requirements the rotation must satisfy.
type LuksToken struct {
	ID         uuid.UUID
	DeviceID   string
	ActionID   string
	Token      string
	MinLength  int32
	Complexity int32
	CreatedAt  time.Time
	ExpiresAt  time.Time
	Used       bool
}

// CreateLuksTokenParams is the input shape for minting a fresh
// retrieval token.
type CreateLuksTokenParams struct {
	DeviceID   string
	ActionID   string
	Token      string
	MinLength  int32
	Complexity int32
}

// ConsumeLuksTokenParams is the input shape for the one-shot
// validate+consume check the gateway proxy performs when a device
// presents a token. The query returns the matching row AND marks it
// used in one statement — replay yields ErrNotFound.
type ConsumeLuksTokenParams struct {
	Token    string
	DeviceID string
}

// LuksKeyByActionKey is the composite (device, action) lookup used
// by the gateway proxy when the agent asks for the current key
// matching a known action.
type LuksKeyByActionKey struct {
	DeviceID string
	ActionID string
}

// LuksRevocationStreamKey is the composite lookup the inbox worker
// uses to find the event-stream ID that holds the revocation
// request → revoked/failed chain for a (device, action).
type LuksRevocationStreamKey struct {
	DeviceID string
	ActionID string
}

// LuksRepo reads LUKS-rotation state + manages the per-retrieval
// one-time token. Token writes are repo-side (no event store
// involvement); key rotation flows through events.
type LuksRepo interface {
	// ListCurrent returns the current LUKS key row per (action,
	// device_path) on the device.
	ListCurrent(ctx context.Context, deviceID string) ([]LuksKey, error)

	// ListHistory returns every rotation for the device, most
	// recent first.
	ListHistory(ctx context.Context, deviceID string) ([]LuksKey, error)

	// GetCurrentForAction returns the current key for a (device,
	// action) pair — the gateway proxy uses this when the agent
	// presents a token to redeem.
	GetCurrentForAction(ctx context.Context, key LuksKeyByActionKey) (LuksKey, error)

	// CreateToken mints a fresh one-time retrieval token row.
	CreateToken(ctx context.Context, p CreateLuksTokenParams) (LuksToken, error)

	// ConsumeToken validates and burns a presented token in one
	// statement. Returns ErrNotFound when the token is unknown,
	// already used, expired, or mismatched on device_id.
	ConsumeToken(ctx context.Context, p ConsumeLuksTokenParams) (LuksToken, error)

	// GetRevocationStreamID looks up the event-stream ID for the
	// pending revocation request on a (device, action). Used by
	// the inbox worker to append the terminal event to the SAME
	// stream so the three-phase projection stitches together.
	GetRevocationStreamID(ctx context.Context, key LuksRevocationStreamKey) (string, error)
}
