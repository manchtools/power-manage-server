package store

import (
	"context"
	"time"
)

// TotpRecord is the per-user TOTP enrollment row. SecretEncrypted
// stays encrypted-at-rest; the caller decrypts with internal/crypto
// when it actually needs the secret to verify a code.
//
// ProjectionVersion tracks the stream_version of the last event
// applied to this row (the MarkTotpBackupCodeUsed +
// RegenerateTotpBackupCodes queries set it explicitly). Exposed so
// the backup-code consume path (audit F-07) can pass
// projection_version + 1 to AppendEventWithVersion and serialise
// concurrent attempts via the event store's UNIQUE constraint.
type TotpRecord struct {
	UserID            string
	SecretEncrypted   string
	Verified          bool
	Enabled           bool
	BackupCodesHash   []string
	BackupCodesUsed   []bool
	CreatedAt         time.Time
	UpdatedAt         time.Time
	ProjectionVersion int64
}

// TotpStatus is the narrow "do I need to challenge this user?" shape
// returned to the web client for the login flow + settings UI.
// Intentionally omits secret material — there is no method here that
// could leak it.
type TotpStatus struct {
	Enabled              bool
	BackupCodesRemaining int32
}

// TotpRepo reads TOTP enrollment state. Writes (enrol, verify,
// disable, regenerate backup codes) flow through events.
type TotpRepo interface {
	// GetByUserID returns the full enrollment row for the user.
	// Returns ErrNotFound when no enrollment exists.
	GetByUserID(ctx context.Context, userID string) (TotpRecord, error)

	// GetStatus returns the lean status shape used by login and
	// settings. Returns ErrNotFound when no enrollment exists —
	// handlers should map that to "enabled = false" rather than
	// surfacing the error to the user.
	GetStatus(ctx context.Context, userID string) (TotpStatus, error)
}
