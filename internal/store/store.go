// Package store provides database access for the control server.
//
// The package boundary is the enforcement mechanism for the audit
// contract. The connection pool and the generated query handle are
// unexported and no exported method hands either of them out, so there
// is exactly one door through which a state mutation can reach the
// database: WithAudit, which writes the operation row and its effect
// rows in the same transaction as the mutation. Reads are exported
// individually. A handler cannot mutate without an audit record
// because there is no call it could make to do so.
package store

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib" // pgx database/sql driver, used by the migration runner
	"github.com/pressly/goose/v3"

	"github.com/manchtools/power-manage/server/internal/store/generated"
	"github.com/manchtools/power-manage/server/internal/store/migrations"
)

// Tx is the transaction-bound query handle handed to a WithAudit
// callback. It is the generated query surface: everything reachable
// through it commits or rolls back with the audit rows written by the
// same call.
type Tx = generated.Queries

// Store owns the connection pool and the primitives every domain
// shares: the audited transaction spine, advisory locks, chain
// verification and the migration runner.
type Store struct {
	now     func() time.Time // clock seam; time.Now in production
	pool    *pgxpool.Pool
	queries *generated.Queries

	// advisoryMu serialises LOCAL goroutines competing for an advisory
	// lock BEFORE they take a pooled connection. Without it, N
	// concurrent callers each hold a connection while blocking on
	// pg_advisory_lock; once N reaches the pool size the lock holder
	// cannot acquire the extra connections its callback needs and the
	// whole set deadlocks. Waiters queue here holding nothing.
	advisoryMu sync.Mutex

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

// Pool tuning. statementTimeout bounds a SINGLE statement's wall clock
// so a pathological query cannot pin a connection indefinitely; it is
// per-statement, not per-transaction. Migrations run on a separate
// database/sql connection and are exempt.
const (
	statementTimeout    = 30 * time.Second
	poolMaxConns        = 20
	poolMaxConnLifetime = time.Hour
)

func newPool(ctx context.Context, connString string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(connString)
	if err != nil {
		return nil, fmt.Errorf("parse pool config: %w", err)
	}
	if cfg.ConnConfig.RuntimeParams == nil {
		cfg.ConnConfig.RuntimeParams = map[string]string{}
	}
	// Respect an operator-provided statement_timeout in the DSN;
	// otherwise apply ours. Postgres reads a bare integer as milliseconds.
	if _, set := cfg.ConnConfig.RuntimeParams["statement_timeout"]; !set {
		cfg.ConnConfig.RuntimeParams["statement_timeout"] = strconv.FormatInt(statementTimeout.Milliseconds(), 10)
	}
	cfg.MaxConns = poolMaxConns
	cfg.MaxConnLifetime = poolMaxConnLifetime
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("create connection pool: %w", err)
	}
	return pool, nil
}

// New connects and brings the schema up to date. Only the control
// process manages the schema.
func New(ctx context.Context, connString string) (*Store, error) {
	pool, err := newPool(ctx, connString)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}

	// goose speaks database/sql, so migrations run on the stdlib
	// adapter rather than the pgx pool.
	sqlDB, err := sql.Open("pgx", connString)
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("open database for migrations: %w", err)
	}
	defer func() { _ = sqlDB.Close() }()

	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("postgres"); err != nil {
		pool.Close()
		return nil, fmt.Errorf("set goose dialect: %w", err)
	}
	if err := goose.Up(sqlDB, "."); err != nil {
		pool.Close()
		return nil, fmt.Errorf("run migrations: %w", err)
	}

	return newStore(pool), nil
}

// NewWithoutMigrations connects to a database whose schema is already
// current.
func NewWithoutMigrations(ctx context.Context, connString string) (*Store, error) {
	pool, err := newPool(ctx, connString)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}
	return newStore(pool), nil
}

func newStore(pool *pgxpool.Pool) *Store {
	return &Store{
		now:     time.Now,
		pool:    pool,
		queries: generated.New(pool),
	}
}

// Close releases the pool.
func (s *Store) Close() {
	s.pool.Close()
}

// WithAdvisoryLock runs fn while holding a session-level advisory lock
// on key, serialising every caller that uses the same key on this
// database. The lock spans the whole of fn, so a read-side guard that
// checks state and then writes is atomic against a concurrent caller.
//
// The lock is taken on a dedicated pooled connection and explicitly
// released: releasing a pooled connection does not close the session,
// so an unreleased session lock would leak. The release is detached
// from ctx so a cancelled request still frees the lock.
func (s *Store) WithAdvisoryLock(ctx context.Context, key int64, fn func() error) (err error) {
	// Serialise local goroutines BEFORE taking a connection; see
	// advisoryMu.
	s.advisoryMu.Lock()
	defer s.advisoryMu.Unlock()

	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire connection for advisory lock: %w", err)
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", key); err != nil {
		return fmt.Errorf("acquire advisory lock %d: %w", key, err)
	}
	defer func() {
		if _, uerr := conn.Exec(context.WithoutCancel(ctx), "SELECT pg_advisory_unlock($1)", key); uerr != nil && err == nil {
			err = fmt.Errorf("release advisory lock %d: %w", key, uerr)
		}
	}()

	return fn()
}

// TryWithAdvisoryLock is the non-blocking sibling of WithAdvisoryLock:
// it runs fn only if the lock is free across the whole database, and
// reports ran=false without running fn otherwise.
func (s *Store) TryWithAdvisoryLock(ctx context.Context, key int64, fn func() error) (ran bool, err error) {
	s.advisoryMu.Lock()
	defer s.advisoryMu.Unlock()

	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return false, fmt.Errorf("acquire connection for advisory lock: %w", err)
	}
	defer conn.Release()

	var got bool
	if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", key).Scan(&got); err != nil {
		return false, fmt.Errorf("try advisory lock %d: %w", key, err)
	}
	if !got {
		return false, nil
	}
	defer func() {
		if _, uerr := conn.Exec(context.WithoutCancel(ctx), "SELECT pg_advisory_unlock($1)", key); uerr != nil && err == nil {
			err = fmt.Errorf("release advisory lock %d: %w", key, uerr)
		}
	}()

	return true, fn()
}

// withTx runs fn inside a transaction and hands it both the raw
// transaction (for session-scoped settings) and the transaction-bound
// query handle.
//
// Package-private on purpose: an exported generic transaction would be
// a second, unaudited door into the mutation path, and the audit
// contract is that there is only one. The audited primitives in
// audit.go are its only callers.
func (s *Store) withTx(ctx context.Context, fn func(pgx.Tx, *generated.Queries) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := fn(tx, s.queries.WithTx(tx)); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
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
