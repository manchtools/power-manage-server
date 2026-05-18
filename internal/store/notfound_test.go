package store_test

// Pure-Go classification tests for the store sentinels. The DB-backed
// AppendEvent retry / conflict paths are tested in store_test.go and
// listener_test.go; this file covers the classifiers themselves so a
// future backend swap (MySQL, SQLite) can drop in its native error and
// extend IsNotFound / IsVersionConflict without breaking handler-side
// code that already routes through these recognizers.

import (
	"database/sql"
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"

	"github.com/manchtools/power-manage/server/internal/store"
)

func TestIsNotFound(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"unrelated", errors.New("boom"), false},
		{"sentinel", store.ErrNotFound, true},
		{"sentinel wrapped", fmt.Errorf("lookup failed: %w", store.ErrNotFound), true},
		{"pgx.ErrNoRows", pgx.ErrNoRows, true},
		{"pgx.ErrNoRows wrapped", fmt.Errorf("query: %w", pgx.ErrNoRows), true},
		// pgx.ErrNoRows wraps sql.ErrNoRows (so an unwrapped pgx
		// error still classifies), but a bare sql.ErrNoRows did NOT
		// come from a store-backend query and intentionally falls
		// through to false — migration code uses database/sql and
		// must not be conflated with the repo-layer's no-rows signal.
		{"sql.ErrNoRows direct", sql.ErrNoRows, false},
		// IsVersionConflict's signal must not collide with IsNotFound.
		{"version-conflict sentinel", store.ErrVersionConflict, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, store.IsNotFound(tc.err))
		})
	}
}

func TestIsVersionConflict(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"unrelated", errors.New("boom"), false},
		{"sentinel", store.ErrVersionConflict, true},
		{"sentinel wrapped", fmt.Errorf("append event: %w", store.ErrVersionConflict), true},
		{"pgconn 23505", &pgconn.PgError{Code: "23505"}, true},
		{"pgconn 23505 wrapped", fmt.Errorf("query: %w", &pgconn.PgError{Code: "23505"}), true},
		{"pgconn other code", &pgconn.PgError{Code: "23503"}, false}, // foreign_key_violation
		{"pgconn check violation", &pgconn.PgError{Code: "23514"}, false},
		// IsNotFound's signal must not collide with IsVersionConflict.
		{"not-found sentinel", store.ErrNotFound, false},
		{"pgx.ErrNoRows", pgx.ErrNoRows, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, store.IsVersionConflict(tc.err))
		})
	}
}

// TestErrVersionConflict_UnwrapPath documents the wrap-shape callers
// depend on: AppendEvent / AppendEventWithVersion wrap conflicts with
// fmt.Errorf("%w: ...", ErrVersionConflict), so errors.Is + the
// IsVersionConflict recognizer must both classify the wrapped error.
// A regression here would silently force handler-side callers back to
// matching error strings.
func TestErrVersionConflict_UnwrapPath(t *testing.T) {
	wrapped := fmt.Errorf("%w: expected version 7 but stream was modified", store.ErrVersionConflict)
	assert.True(t, errors.Is(wrapped, store.ErrVersionConflict), "errors.Is should match wrapped sentinel")
	assert.True(t, store.IsVersionConflict(wrapped), "IsVersionConflict should match wrapped sentinel")
}
