package store

import (
	"database/sql"
	"errors"
	"strings"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// ErrNotFound is the canonical "no row matched" sentinel for store reads.
// Code outside this package uses IsNotFound instead of depending on a driver.
var ErrNotFound = errors.New("not found")

// IsNotFound reports whether err signals a missing row.
func IsNotFound(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, ErrNotFound) || errors.Is(err, sql.ErrNoRows)
}

func translateNotFound(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

// ErrConflict is the canonical "a conditional write lost" sentinel.
var ErrConflict = errors.New("conflict")

// IsConflict reports whether err is a semantic conflict or a SQLite unique
// constraint that represents the same lost conditional write.
func IsConflict(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrConflict) {
		return true
	}
	var sqliteErr *sqlite.Error
	if !errors.As(err, &sqliteErr) {
		return false
	}
	return sqliteErr.Code() == sqlite3.SQLITE_CONSTRAINT_UNIQUE ||
		sqliteErr.Code() == sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY
}

// IsAppendOnlyViolation reports whether SQLite's audit trigger refused an
// UPDATE or DELETE. The message check distinguishes it from unrelated trigger
// constraints.
func IsAppendOnlyViolation(err error) bool {
	if err == nil {
		return false
	}
	var sqliteErr *sqlite.Error
	return errors.As(err, &sqliteErr) &&
		sqliteErr.Code() == sqlite3.SQLITE_CONSTRAINT_TRIGGER &&
		strings.Contains(sqliteErr.Error(), "append-only")
}
