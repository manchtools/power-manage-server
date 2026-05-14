package store

import (
	"errors"

	"github.com/jackc/pgx/v5"
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
