// Package testdb exposes raw SQLite access to black-box integration tests.
// Production store code deliberately keeps its database handle private.
package testdb

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"
)

// DB provides the context-first method shape used by integration fixtures.
type DB struct{ db *sql.DB }

// Tx provides the context-first transaction shape used by integration tests.
type Tx struct{ tx *sql.Tx }

// Conn is one pinned database/sql connection for connection-local PRAGMAs.
type Conn struct{ conn *sql.Conn }

// Rows and Row preserve the context-first conveniences used by the existing
// black-box fixtures while the production store uses database/sql directly.
type Rows struct{ rows *sql.Rows }
type Row struct {
	row *sql.Row
	err error
}

// Open connects a raw test handle to an existing SQLite file.
func Open(ctx context.Context, path string) (*DB, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve SQLite test path: %w", err)
	}
	dsn := (&url.URL{Scheme: "file", Path: absolute}).String() +
		"?_pragma=busy_timeout%285000%29&_pragma=foreign_keys%281%29&_time_format=sqlite"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open raw SQLite test database: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping raw SQLite test database: %w", err)
	}
	return &DB{db: db}, nil
}

// Close releases the raw test handle.
func (db *DB) Close() { _ = db.db.Close() }

// CommandTag is the rows-affected portion tests need from a mutation.
type CommandTag struct{ rows int64 }

// RowsAffected reports the mutation count.
func (tag CommandTag) RowsAffected() int64 { return tag.rows }

// Exec executes raw fixture SQL.
func (db *DB) Exec(ctx context.Context, statement string, args ...any) (CommandTag, error) {
	return exec(ctx, db.db, statement, args...)
}

// Begin starts a raw fixture transaction.
func (db *DB) Begin(ctx context.Context) (*Tx, error) {
	tx, err := db.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	return &Tx{tx: tx}, nil
}

// Conn acquires one dedicated connection. Tests that change a PRAGMA must use
// this handle for the PRAGMA and every statement affected by it.
func (db *DB) Conn(ctx context.Context) (*Conn, error) {
	conn, err := db.db.Conn(ctx)
	if err != nil {
		return nil, err
	}
	return &Conn{conn: conn}, nil
}

// Close returns the dedicated connection to the pool.
func (conn *Conn) Close() error { return conn.conn.Close() }

// Exec executes fixture SQL on a dedicated connection.
func (conn *Conn) Exec(ctx context.Context, statement string, args ...any) (CommandTag, error) {
	return exec(ctx, conn.conn, statement, args...)
}

// Exec executes raw fixture SQL inside the transaction.
func (tx *Tx) Exec(ctx context.Context, statement string, args ...any) (CommandTag, error) {
	return exec(ctx, tx.tx, statement, args...)
}

type execer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func exec(ctx context.Context, target execer, statement string, args ...any) (CommandTag, error) {
	args, err := sqliteArgs(args)
	if err != nil {
		return CommandTag{}, err
	}
	result, err := target.ExecContext(ctx, statement, args...)
	if err != nil {
		return CommandTag{}, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return CommandTag{}, err
	}
	return CommandTag{rows: rows}, nil
}

// Commit commits the raw fixture transaction.
func (tx *Tx) Commit(_ context.Context) error { return tx.tx.Commit() }

// Rollback rolls back the raw fixture transaction.
func (tx *Tx) Rollback(_ context.Context) error { return tx.tx.Rollback() }

// Query executes a raw fixture query.
func (db *DB) Query(ctx context.Context, statement string, args ...any) (*Rows, error) {
	args, err := sqliteArgs(args)
	if err != nil {
		return nil, err
	}
	rows, err := db.db.QueryContext(ctx, statement, args...)
	if err != nil {
		return nil, err
	}
	return &Rows{rows: rows}, nil
}

// QueryRow executes a raw fixture query expected to return one row.
func (db *DB) QueryRow(ctx context.Context, statement string, args ...any) *Row {
	args, err := sqliteArgs(args)
	if err != nil {
		return &Row{err: err}
	}
	return &Row{row: db.db.QueryRowContext(ctx, statement, args...)}
}

// Next advances to the next result row.
func (rows *Rows) Next() bool { return rows.rows.Next() }

// Close releases the query cursor.
func (rows *Rows) Close() error { return rows.rows.Close() }

// Err reports iteration errors.
func (rows *Rows) Err() error { return rows.rows.Err() }

// Scan decodes SQLite JSON arrays into the []string destinations used by old
// fixtures. Production queries use sqlitetype.StringList directly.
func (rows *Rows) Scan(dest ...any) error { return scanStringLists(rows.rows.Scan, dest) }

// Scan reads the single row, including SQLite JSON string-list adaptation.
func (row *Row) Scan(dest ...any) error {
	if row.err != nil {
		return row.err
	}
	return scanStringLists(row.row.Scan, dest)
}

func sqliteArgs(args []any) ([]any, error) {
	converted := append([]any(nil), args...)
	for i, arg := range converted {
		if strings, ok := arg.([]string); ok {
			raw, err := json.Marshal(strings)
			if err != nil {
				return nil, fmt.Errorf("encode SQLite string-list argument %d: %w", i+1, err)
			}
			converted[i] = driver.Value(string(raw))
		}
	}
	return converted, nil
}

func scanStringLists(scan func(...any) error, dest []any) error {
	type stringListTarget struct {
		destination *[]string
		raw         sql.NullString
	}
	converted := append([]any(nil), dest...)
	targets := make([]stringListTarget, 0, len(dest))
	for i, destination := range converted {
		if strings, ok := destination.(*[]string); ok {
			targets = append(targets, stringListTarget{destination: strings})
			converted[i] = &targets[len(targets)-1].raw
		}
	}
	if err := scan(converted...); err != nil {
		return err
	}
	for _, target := range targets {
		if !target.raw.Valid {
			*target.destination = nil
			continue
		}
		if err := json.Unmarshal([]byte(target.raw.String), target.destination); err != nil {
			return fmt.Errorf("decode SQLite string list: %w", err)
		}
	}
	return nil
}

// Backup writes a consistent SQLite snapshot using the engine's VACUUM INTO
// primitive. The destination must not already exist.
func (db *DB) Backup(ctx context.Context, destination string) error {
	if strings.TrimSpace(destination) == "" {
		return fmt.Errorf("SQLite backup destination is required")
	}
	if _, err := db.db.ExecContext(ctx, "VACUUM INTO ?", destination); err != nil {
		return fmt.Errorf("backup SQLite database: %w", err)
	}
	return nil
}
