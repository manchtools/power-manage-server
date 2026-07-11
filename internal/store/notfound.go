package store

import (
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// ErrNotFound is the canonical "no row matched" sentinel for store
// reads. Handlers, projectors, scim/idp glue — anything outside the
// store package — must test for not-found via store.IsNotFound(err)
// rather than reaching for pgx.ErrNoRows directly. The pgx symbol is
// an implementation detail of the Postgres backend; pinning the
// abstraction here lets a future backend register its own no-rows
// error without touching every caller. See tracker #242.
var ErrNotFound = errors.New("not found")

// IsNotFound reports whether err signals a missing row from any
// supported storage backend. Today that's pgx.ErrNoRows or
// ErrNotFound itself (callers that already wrap with errors.Join
// also match). Future backends extend this function — no other
// recognizer should be needed at call sites.
func IsNotFound(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, ErrNotFound) || errors.Is(err, pgx.ErrNoRows)
}

// ErrVersionConflict is the canonical "optimistic-concurrency lost"
// sentinel for AppendEvent writes. The Postgres backend recognises a
// unique-violation on (stream_type, stream_id, stream_version) as the
// conflict signal (`pgconn.PgError.Code == "23505"`); a future MySQL /
// SQLite backend would map ER_DUP_ENTRY 1062 / SQLITE_CONSTRAINT_UNIQUE
// onto the same sentinel without callers needing to know.
var ErrVersionConflict = errors.New("version conflict")

// IsVersionConflict reports whether err signals a stream-version
// collision on AppendEvent. Mirrors IsNotFound — the only intended
// recognizer for OCC failures outside the store package.
func IsVersionConflict(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrVersionConflict) {
		return true
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return true
	}
	return false
}

// isDeadlock reports whether err is a Postgres deadlock (SQLSTATE
// 40P01). A deadlock aborts the whole transaction, so — like a version
// conflict — the batch-append path (AppendEvents) retries the entire
// transaction rather than surfacing a transient failure. Two overlapping
// multi-stream batches that lock the same streams in opposite orders are
// the classic trigger; retrying resolves them.
//
// Deliberately NOT folded into IsVersionConflict: a deadlock is not an
// optimistic-concurrency loss, and IsVersionConflict's handler callers
// map it to a 409/Aborted status where a deadlock does not belong.
func isDeadlock(err error) bool {
	if err == nil {
		return false
	}
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "40P01"
}
