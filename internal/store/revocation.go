package store

import (
	"context"
	"fmt"
	"time"

	"github.com/manchtools/power-manage/server/internal/store/generated"
)

// RevocationChecker answers "is this certificate revoked" during the
// mTLS handshake with an indexed primary-key lookup.
//
// Deliberately not a cache. A periodically refreshed snapshot is stale
// for up to one refresh interval, which re-opens on the read side
// exactly the window RevokeInTx closes on the write side: writing the
// revocation in the same transaction as its cause buys nothing if the
// gate goes on admitting the certificate until the next tick.
//
// A lookup error is returned, never swallowed; every caller must treat
// an error as revoked and fail the handshake.
type RevocationChecker struct {
	store *Store
}

// NewRevocationChecker returns a checker backed by st.
func NewRevocationChecker(st *Store) *RevocationChecker {
	return &RevocationChecker{store: st}
}

// IsRevoked reports whether fingerprint is currently revoked.
func (c *RevocationChecker) IsRevoked(ctx context.Context, fingerprint string) (bool, error) {
	revoked, err := c.store.queries.IsCertificateRevoked(ctx, fingerprint)
	if err != nil {
		return false, fmt.Errorf("revocation lookup: %w", err)
	}
	return revoked, nil
}

// RevokeInTx records a revocation on the transaction handle a WithAudit
// callback holds, so the row lands atomically with whatever caused it
// and with the audit record of that cause.
//
// The signature takes the transaction handle rather than reading a
// pool handle precisely so it cannot be called outside an audited
// transaction: certificate renewal and device deletion must not be
// able to commit while their revocation is still pending, which would
// leave the superseded certificate accepted for as long as the
// revocation kept failing.
func RevokeInTx(ctx context.Context, tx *Tx, fingerprint string, notAfter time.Time, reason string) error {
	if fingerprint == "" {
		return fmt.Errorf("refusing to revoke an empty fingerprint")
	}
	if _, err := tx.RevokeCertificate(ctx, generated.RevokeCertificateParams{
		Fingerprint: fingerprint,
		NotAfter:    notAfter,
		Reason:      reason,
	}); err != nil {
		return fmt.Errorf("revoke certificate: %w", err)
	}
	return nil
}

// DeleteExpiredRevocationsInTx drops revocation rows for certificates
// that have expired: such a certificate can no longer authenticate
// anything, so the row is dead weight, and without this the table
// grows by one row per certificate rotation forever.
//
// Transaction-bound like RevokeInTx. Deleting security state is a
// mutation, so it runs inside a BACKGROUND_WRITER-class audited
// operation and is attributable like any other.
func DeleteExpiredRevocationsInTx(ctx context.Context, tx *Tx) (int64, error) {
	n, err := tx.DeleteExpiredRevocations(ctx, time.Now().UTC().Add(-7*24*time.Hour))
	if err != nil {
		return 0, fmt.Errorf("delete expired revocations: %w", err)
	}
	return n, nil
}
