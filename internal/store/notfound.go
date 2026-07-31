package store

import (
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// ErrNotFound is the canonical "no row matched" sentinel for store
// reads. Code outside this package must test for it via IsNotFound
// rather than reaching for a driver error: the driver symbol is an
// implementation detail of the Postgres backend, and pinning the
// recognizer here lets a future backend register its own no-rows error
// without touching call sites.
var ErrNotFound = errors.New("not found")

// IsNotFound reports whether err signals a missing row. Extending this
// function is how a new backend joins; no other recognizer should be
// needed at call sites.
func IsNotFound(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, ErrNotFound) || errors.Is(err, pgx.ErrNoRows)
}

// translateNotFound maps the driver's no-rows error to ErrNotFound at
// the point a read leaves this package. The original error is dropped
// on purpose: callers depend on IsNotFound and have no use for the
// backend-specific cause. Every other error passes through unchanged
// so a wrapping caller keeps the underlying chain.
func translateNotFound(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

// ErrConflict is the canonical "a conditional write lost" sentinel.
// Consume-once tokens, delivery transitions, registration, revocation
// and the other semantic state machines write conditionally; when the
// condition no longer holds, the caller sees this rather than a
// backend-specific constraint error. The Postgres backend recognises a
// unique violation (SQLSTATE 23505) as the signal.
var ErrConflict = errors.New("conflict")

// IsConflict reports whether err signals a lost conditional write.
func IsConflict(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrConflict) {
		return true
	}
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// IsAppendOnlyViolation reports whether err is the audit log's
// append-only guard refusing an UPDATE, DELETE or TRUNCATE. The guard
// raises SQLSTATE 23001 (restrict_violation), which no ordinary write
// in this schema produces.
func IsAppendOnlyViolation(err error) bool {
	if err == nil {
		return false
	}
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23001"
}
