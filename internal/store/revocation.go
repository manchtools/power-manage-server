package store

import (
	"context"
	"fmt"
	"time"

	"github.com/manchtools/power-manage/server/internal/store/generated"
)

// RevocationChecker answers "is this certificate revoked" during the mTLS
// handshake by querying the table directly. It satisfies mtls.RevocationChecker.
//
// Deliberately NOT a cache. The predecessor kept a periodically-refreshed
// snapshot because each check would otherwise have been a Valkey round-trip.
// Revocations now live in this database, so the check is a local indexed
// primary-key lookup — and a snapshot would be actively wrong here: it is stale
// for up to one refresh interval, which re-opens on the read side exactly the
// window AppendEventAndRevoke closes on the write side. Writing the revocation
// in the same transaction buys nothing if the gate goes on admitting the
// certificate until the next tick.
//
// A lookup error is returned, never swallowed: the gate fails closed on it.
type RevocationChecker struct {
	store *Store
}

// NewRevocationChecker returns a checker backed by st.
func NewRevocationChecker(st *Store) *RevocationChecker {
	return &RevocationChecker{store: st}
}

// IsRevoked reports whether fingerprint is currently revoked. An error means
// "unknown", and every caller must treat that as revoked.
func (c *RevocationChecker) IsRevoked(ctx context.Context, fingerprint string) (bool, error) {
	revoked, err := c.store.Queries().IsCertificateRevoked(ctx, fingerprint)
	if err != nil {
		return false, fmt.Errorf("revocation lookup: %w", err)
	}
	return revoked, nil
}

// DeleteExpiredRevocations drops revocation rows whose certificate has expired:
// such a certificate can no longer authenticate anything, so the row is dead
// weight. Without this the table grows by one row per certificate rotation
// forever, which contradicts calling it TTL-bounded.
func (s *Store) DeleteExpiredRevocations(ctx context.Context) (int64, error) {
	n, err := s.Queries().DeleteExpiredRevocations(ctx)
	if err != nil {
		return 0, fmt.Errorf("delete expired revocations: %w", err)
	}
	return n, nil
}

// RevokeInTx records a revocation on the given transaction, so the row lands
// atomically with whatever caused it.
//
// This is the whole point of the signature taking *Queries rather than reading
// s.Queries() itself. Certificate renewal and device deletion previously revoked
// on a BEST-EFFORT basis after their own write had already committed, which
// leaves a window where the superseded certificate is still accepted. Spec 41
// criterion 6 closes that: either both land or neither does.
func RevokeInTx(ctx context.Context, q *Queries, fingerprint string, notAfter time.Time, reason string) error {
	if fingerprint == "" {
		return fmt.Errorf("refusing to revoke an empty fingerprint")
	}
	if _, err := q.RevokeCertificate(ctx, generated.RevokeCertificateParams{
		Fingerprint: fingerprint,
		NotAfter:    notAfter,
		Reason:      reason,
	}); err != nil {
		return fmt.Errorf("revoke certificate: %w", err)
	}
	return nil
}

// AppendEventAndRevoke appends event and revokes fingerprint in ONE transaction,
// then fires post-commit listeners exactly as AppendEvent does.
//
// Spec 41 criterion 6. The callers — certificate renewal and device deletion —
// each used to append their event, let it commit, and then revoke separately on
// a best-effort basis, logging on failure. That ordering leaves the superseded
// certificate accepted for as long as the revocation keeps failing, and the
// renewal path documented it as intentional because a revocation failure "must
// not fail the renewal the agent already committed to". With revocation in the
// same database that tradeoff is unnecessary: the write is local, so it can be
// atomic instead of best-effort.
//
// Retries mirror AppendEvent's: a version conflict re-runs the whole
// transaction, revocation included, which is safe because RevokeCertificate is
// idempotent on the fingerprint primary key.
func (s *Store) AppendEventAndRevoke(
	ctx context.Context,
	event Event,
	fingerprint string,
	notAfter time.Time,
	reason string,
) error {
	pe, err := s.prepareEvent(ctx, event)
	if err != nil {
		return err
	}

	const maxRetries = 5
	for i := 0; i < maxRetries; i++ {
		var row PersistedEvent
		txErr := s.WithTx(ctx, func(q *Queries) error {
			r, aerr := s.appendOne(ctx, q, pe)
			if aerr != nil {
				return aerr
			}
			if rerr := RevokeInTx(ctx, q, fingerprint, notAfter, reason); rerr != nil {
				return rerr
			}
			row = r
			return nil
		})
		if txErr != nil {
			if IsVersionConflict(txErr) {
				if i < maxRetries-1 {
					continue
				}
				return fmt.Errorf("%w: stream was modified concurrently after %d retries", ErrVersionConflict, maxRetries)
			}
			return fmt.Errorf("append event and revoke: %w", txErr)
		}
		s.fireListeners(ctx, row)
		return nil
	}
	return fmt.Errorf("append event and revoke: exhausted retries")
}
