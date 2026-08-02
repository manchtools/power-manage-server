// Package store provides database access for the control server.
//
// The package boundary is the enforcement mechanism for the audit
// contract. The connection pool and generated query handle are unexported.
// Ordinary state changes reach the database through WithAudit, which writes
// their operation and effects in the same transaction. The one named exception
// is bounded, coalesced heartbeat telemetry: liveness samples are not security
// evidence and do not enter the serialized audit chain. No generic query handle
// escapes this package.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"github.com/manchtools/power-manage/server/internal/store/generated"
	"github.com/manchtools/power-manage/server/internal/store/sqliteschema"
)

// Tx is the transaction-bound query handle handed to a WithAudit callback.
// Generated domain queries stay exported through the embedded handle; raw SQL
// remains package-private so other packages cannot bypass the audited store
// surface.
type Tx struct {
	*generated.Queries
	raw *sql.Tx
}

// Store owns the connection pool and the primitives every domain
// shares: the audited transaction spine, advisory locks, chain
// verification and the migration runner.
type Store struct {
	now     func() time.Time // clock seam; time.Now in production
	db      *sql.DB
	queries *generated.Queries

	// A single control process owns the SQLite file. This mutex serializes the
	// audited writer before it enters SQLite's own single-writer path.
	writeMu sync.Mutex

	// wireMu guards the fields wired once at boot and read afterwards.
	wireMu sync.RWMutex

	logger *slog.Logger
}

// SetLogger plumbs a logger for the store's own diagnostics. Optional.
func (s *Store) SetLogger(logger *slog.Logger) {
	s.wireMu.Lock()
	s.logger = logger
	s.wireMu.Unlock()
}

const sqliteOpenConnections = 10

// New opens the authoritative SQLite file and creates the clean baseline when
// the file is empty. The project is pre-alpha, so there is no PostgreSQL data
// migration or compatibility path.
func New(ctx context.Context, path string) (*Store, error) {
	db, err := openSQLite(ctx, path, true)
	if err != nil {
		return nil, err
	}
	if err := initializeSQLite(ctx, db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return newStore(db), nil
}

// NewWithoutMigrations opens an already-initialized SQLite file. It is used by
// one-shot commands that must not create a database accidentally.
func NewWithoutMigrations(ctx context.Context, path string) (*Store, error) {
	db, err := openSQLite(ctx, path, false)
	if err != nil {
		return nil, err
	}
	version, err := sqliteSchemaVersion(ctx, db)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	if version != 1 {
		_ = db.Close()
		return nil, fmt.Errorf("open SQLite database: schema version is %d, want 1", version)
	}
	return newStore(db), nil
}

func openSQLite(ctx context.Context, path string, create bool) (*sql.DB, error) {
	if ctx == nil || strings.TrimSpace(path) == "" {
		return nil, errors.New("open SQLite database: path is required")
	}
	if err := prepareSQLiteFile(path, create); err != nil {
		return nil, err
	}
	dsn, err := sqliteDSN(path)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open SQLite database: %w", err)
	}
	db.SetMaxOpenConns(sqliteOpenConnections)
	db.SetMaxIdleConns(sqliteOpenConnections)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping SQLite database: %w", err)
	}
	return db, nil
}

func prepareSQLiteFile(path string, create bool) error {
	if path == ":memory:" || strings.HasPrefix(path, "file:") {
		return nil
	}
	flags := os.O_RDWR
	if create {
		flags |= os.O_CREATE
	}
	file, err := os.OpenFile(path, flags, 0o600)
	if err != nil {
		return fmt.Errorf("open SQLite database file: %w", err)
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return fmt.Errorf("secure SQLite database file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close SQLite database file: %w", err)
	}
	return nil
}

func sqliteDSN(path string) (string, error) {
	var base string
	if path == ":memory:" {
		base = "file:power-manage?mode=memory&cache=shared"
	} else if strings.HasPrefix(path, "file:") {
		base = path
	} else {
		absolute, err := filepath.Abs(path)
		if err != nil {
			return "", fmt.Errorf("resolve SQLite path: %w", err)
		}
		base = (&url.URL{Scheme: "file", Path: absolute}).String()
	}
	separator := "?"
	if strings.Contains(base, "?") {
		separator = "&"
	}
	return base + separator +
		"_pragma=busy_timeout%285000%29" +
		"&_pragma=foreign_keys%281%29" +
		"&_pragma=journal_mode%28WAL%29" +
		"&_pragma=synchronous%28FULL%29" +
		"&_time_format=sqlite", nil
}

func initializeSQLite(ctx context.Context, db *sql.DB) error {
	version, err := sqliteSchemaVersion(ctx, db)
	if err != nil {
		return err
	}
	switch version {
	case 0:
		schema, err := sqliteschema.FS.ReadFile("schema.sql")
		if err != nil {
			return fmt.Errorf("read SQLite baseline: %w", err)
		}
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("begin SQLite baseline: %w", err)
		}
		var current int
		if err := tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&current); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("recheck SQLite schema version: %w", err)
		}
		if current != 0 {
			if err := tx.Commit(); err != nil {
				return fmt.Errorf("close SQLite baseline check: %w", err)
			}
			if current == 1 {
				return nil
			}
			return fmt.Errorf("open SQLite database: unsupported schema version %d", current)
		}
		if _, err := tx.ExecContext(ctx, string(schema)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("apply SQLite baseline: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit SQLite baseline: %w", err)
		}
		return nil
	case 1:
		return nil
	default:
		return fmt.Errorf("open SQLite database: unsupported schema version %d", version)
	}
}

func sqliteSchemaVersion(ctx context.Context, db *sql.DB) (int, error) {
	var version int
	if err := db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return 0, fmt.Errorf("read SQLite schema version: %w", err)
	}
	return version, nil
}

func newStore(db *sql.DB) *Store {
	return &Store{
		now:     time.Now,
		db:      db,
		queries: generated.New(db),
	}
}

// Close releases the pool.
func (s *Store) Close() {
	_ = s.db.Close()
}

// Ping verifies that the authoritative database is reachable.
func (s *Store) Ping(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

// withTx runs fn inside a transaction and hands it both the raw
// transaction (for session-scoped settings) and the transaction-bound
// query handle.
//
// Package-private on purpose: an exported generic transaction would be
// a second, unaudited door into the mutation path, and the audit
// contract is that there is only one. The audited primitives and the named
// heartbeat telemetry exception are its only callers.
func (s *Store) withTx(ctx context.Context, fn func(*sql.Tx, *generated.Queries) error) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := fn(tx, s.queries.WithTx(tx)); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}
	return nil
}

func (s *Store) clock() time.Time {
	s.wireMu.RLock()
	now := s.now
	s.wireMu.RUnlock()
	return now()
}
