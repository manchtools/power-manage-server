package store

import (
	"context"
	"time"
)

// UserEncryptionKey is one user's KEK-wrapped data-encryption key
// (spec 19 / ADR 0030). The wrapped form is the ONLY persisted form;
// the plaintext DEK exists in memory only, inside internal/crypto.
type UserEncryptionKey struct {
	UserID     string
	WrappedDEK string
	CreatedAt  time.Time
}

// UserEncryptionKeyRepo manages the crypto-shred key material — the
// sole durable, non-recoverable, non-event-sourced Postgres state.
type UserEncryptionKeyRepo interface {
	// Mint stores a freshly wrapped DEK for the user. First-write-wins:
	// if a key already exists it is NEVER replaced (replacing a DEK that
	// already sealed PII would be an accidental shred); Mint reports
	// created=false in that case and the existing key stays.
	Mint(ctx context.Context, userID, wrappedDEK string) (created bool, err error)

	// Get returns the wrapped DEK for the user. ErrNotFound when the
	// user has no key — which, for a deleted user, IS the graceful
	// erased state (spec 19 AC 9).
	Get(ctx context.Context, userID string) (UserEncryptionKey, error)

	// Shred destroys the user's DEK — the erasure itself. Idempotent:
	// shredding an absent key reports shredded=false, no error.
	Shred(ctx context.Context, userID string) (shredded bool, err error)
}
