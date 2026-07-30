package store

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/manchtools/power-manage/server/internal/store/generated"
)

// RevocationCache answers "is this certificate revoked" during the mTLS
// handshake. It satisfies mtls.RevocationChecker structurally, exactly as the
// Valkey-backed crl.Cache did before spec 41 — the gate itself is unchanged.
//
// Why a cache rather than a query per handshake: the check runs on every
// connection, including a whole fleet reconnecting at once after a control
// restart. A snapshot keeps that path a map lookup. The cost is a bounded
// staleness window, which is the same tradeoff the Valkey cache made.
//
// FAIL-CLOSED UNTIL LOADED is preserved deliberately. A freshly constructed
// cache reports Loaded()==false, and the gate rejects while unloaded: without a
// snapshot we cannot prove a certificate is unrevoked, and admitting it would
// mean a control restart briefly honours revoked certificates. There is no
// opt-out — an earlier NoopRevocationChecker fail-open escape hatch was removed
// as audit finding L11 and is not being reintroduced here.
type RevocationCache struct {
	store  *Store
	logger *slog.Logger

	mu      sync.RWMutex
	revoked map[string]struct{}
	loaded  bool
}

// NewRevocationCache returns an UNLOADED cache. Call Refresh before serving, or
// run Run to keep it fresh; until the first successful load every check fails
// closed.
func NewRevocationCache(st *Store, logger *slog.Logger) *RevocationCache {
	return &RevocationCache{
		store:   st,
		logger:  logger,
		revoked: map[string]struct{}{},
	}
}

// IsRevoked reports whether fingerprint is in the last successful snapshot.
func (c *RevocationCache) IsRevoked(fingerprint string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	_, ok := c.revoked[fingerprint]
	return ok
}

// Loaded reports whether at least one snapshot has been taken. False means the
// gate rejects: see the fail-closed note on the type.
func (c *RevocationCache) Loaded() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.loaded
}

// Refresh replaces the snapshot with every revocation still inside its validity
// window. A failure leaves the previous snapshot in place — a database blip must
// not silently un-revoke a certificate, so the last known-good list keeps
// serving rather than being cleared.
func (c *RevocationCache) Refresh(ctx context.Context) error {
	fps, err := c.store.Queries().ListActiveRevokedFingerprints(ctx)
	if err != nil {
		return fmt.Errorf("refresh revocation snapshot: %w", err)
	}

	next := make(map[string]struct{}, len(fps))
	for _, fp := range fps {
		next[fp] = struct{}{}
	}

	c.mu.Lock()
	c.revoked = next
	c.loaded = true
	c.mu.Unlock()
	return nil
}

// Run refreshes on an interval until ctx is cancelled. A failed refresh is
// logged and retried on the next tick; the previous snapshot stays authoritative
// in the meantime.
func (c *RevocationCache) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := c.Refresh(ctx); err != nil && c.logger != nil {
				c.logger.Warn("certificate revocation refresh failed; keeping previous snapshot",
					"error", err)
			}
		}
	}
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
