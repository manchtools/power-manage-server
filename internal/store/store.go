// Package store provides database access for the control server.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib" // pgx database/sql driver
	"github.com/pressly/goose/v3"

	"github.com/manchtools/power-manage/server/internal/store/generated"
	"github.com/manchtools/power-manage/server/internal/store/migrations"
)

// Re-export generated types for convenience
type Queries = generated.Queries
type PersistedEvent = generated.Event

// Event represents a domain event.
type Event struct {
	StreamType string
	StreamID   string
	EventType  string
	Data       map[string]any
	Metadata   map[string]any
	ActorType  string
	ActorID    string
}

// EventListener is a post-commit hook fired after a successful
// AppendEvent. Listeners are invoked synchronously in registration
// order; a slow listener will stall subsequent listeners on the same
// event. None are allowed to mutate the event row.
//
// Context lifetime: the ctx passed in is the caller's request context
// and will be cancelled as soon as AppendEvent returns. Listeners that
// kick off async work must derive a fresh context (typically via
// context.WithoutCancel + context.WithTimeout) and not rely on the
// passed ctx for downstream DB calls.
//
// Panic isolation: panics from a listener are recovered by
// fireListeners and logged to stderr — the AppendEvent caller sees a
// successful commit even if a listener crashes. This matches the
// "post-commit notification" contract: the event is durable; listener
// failures are observability, not correctness.
type EventListener func(ctx context.Context, ev PersistedEvent)

// RebuildApply replays one event during a RebuildAll pass. It runs
// inside the rebuild's outer transaction, so the supplied *Queries is
// already tx-bound — applier writes commit (or roll back) atomically
// with the surrounding TRUNCATEs and other targets in the same
// rebuild. Applier returns an error to abort the entire rebuild;
// successful no-ops (event type the projector doesn't care about)
// must return nil.
//
// Wired in projectors.WireAll for every Go-ported projector that
// owns an entry in AllRebuildTargets. RebuildAll falls back to the
// PL/pgSQL Function dispatch when no applier is registered for the
// target — preserves operator behaviour for not-yet-ported targets.
//
// Refs manchtools/power-manage-server#125.
type RebuildApply func(ctx context.Context, q *Queries, ev PersistedEvent) error

// Store wraps the database connection and provides access to queries.
type Store struct {
	pool    *pgxpool.Pool
	queries *Queries

	// listenersMu guards listeners + OnEventAppended +
	// rebuildAppliers. Documented usage is "register at boot, then
	// start serving", but Go's race detector won't catch a future
	// caller that registers after AppendEvent is in flight
	// (concurrent slice append + range read is a data race). RWMutex
	// is cheap on the hot read path (fireListeners holds RLock) and
	// lets boot code register without extra ceremony.
	listenersMu sync.RWMutex

	// listeners are invoked after every successful AppendEvent /
	// AppendEventWithVersion. Used by search indexing and (rc11) by
	// the system-action derived-projection reconciler. Direct field
	// access deliberately replaced with RegisterEventListener so we
	// can append additional consumers without callers stomping on
	// each other.
	listeners []EventListener

	// rebuildAppliers maps a rebuild-target name to a Go applier
	// that runOneTarget calls per event in lieu of the no-op
	// PL/pgSQL stub left behind by tracker #107 ports. Populated at
	// boot via projectors.WireAll → RegisterRebuildApply. Lookup is
	// guarded by listenersMu (same boot-once-then-read posture as
	// listeners). See manchtools/power-manage-server#125.
	rebuildAppliers map[string]RebuildApply

	// OnEventAppended is preserved for backwards compatibility with
	// the search-indexing wiring at cmd/control/main.go. Setting it
	// is equivalent to RegisterEventListener; do not read from it
	// outside this file. Guarded by listenersMu — callers that
	// reassign at runtime should go through RegisterEventListener
	// instead. (rc11 review round 4: search-indexer wiring migrated.)
	OnEventAppended func(ctx context.Context, ev PersistedEvent)

	// logger is used by fireListeners to log panic recoveries through
	// the standard logging pipeline instead of os.Stderr. Optional;
	// when nil, falls back to os.Stderr so unit tests that construct
	// a Store directly don't require log plumbing. Set via SetLogger
	// from cmd/{control,indexer}/main.go after construction.
	logger *slog.Logger
}

// SetLogger plumbs a slog.Logger for fireListeners' panic-recovery
// pathway. Optional; when nil, the recovery path falls back to
// os.Stderr (preserved so unit tests that construct Store directly
// keep working). Boot-once posture matches RegisterEventListener,
// but the lock is taken anyway so a future caller that swaps the
// logger after AppendEvent traffic starts doesn't race with the
// reader in fireListeners.
func (s *Store) SetLogger(logger *slog.Logger) {
	s.listenersMu.Lock()
	s.logger = logger
	s.listenersMu.Unlock()
}

// RegisterEventListener appends a post-commit hook. Multiple
// listeners may be registered; they fire in registration order.
// Safe to call concurrently with AppendEvent — the RWMutex serialises
// against fireListeners' read iteration.
func (s *Store) RegisterEventListener(fn EventListener) {
	if fn == nil {
		return
	}
	s.listenersMu.Lock()
	s.listeners = append(s.listeners, fn)
	s.listenersMu.Unlock()
}

// RegisterRebuildApply binds a Go applier to a named rebuild target.
// Subsequent RebuildAll calls dispatch matching events through this
// closure instead of the (now no-op) PL/pgSQL project_<X>_event()
// stub. Re-registering the same name overwrites — boot-time wiring
// is expected to call this once per target.
//
// Refs manchtools/power-manage-server#125.
func (s *Store) RegisterRebuildApply(name string, fn RebuildApply) {
	if fn == nil || name == "" {
		return
	}
	s.listenersMu.Lock()
	if s.rebuildAppliers == nil {
		s.rebuildAppliers = make(map[string]RebuildApply)
	}
	s.rebuildAppliers[name] = fn
	s.listenersMu.Unlock()
}

// rebuildApplyFor returns the registered applier for a target name,
// or nil when no Go applier is wired (in which case runOneTarget
// falls back to PL/pgSQL Function dispatch).
func (s *Store) rebuildApplyFor(name string) RebuildApply {
	s.listenersMu.RLock()
	defer s.listenersMu.RUnlock()
	return s.rebuildAppliers[name]
}

// fireListeners invokes both the legacy OnEventAppended callback (if
// set) and every RegisterEventListener entry. Centralised so the two
// AppendEvent variants stay in sync.
//
// Each listener is wrapped in defer/recover so a panic in one cannot
// fail AppendEvent — the event is already committed, and listeners
// are notifications, not part of the write path. Round-3 review of
// rc11 #77 caught this: a panicking listener used to bubble up
// through AppendEvent and fail the RPC even though the event was
// durable, breaking the "event committed → RPC succeeds" contract.
// Panics route through s.logger when set (cmd/control + cmd/indexer
// call SetLogger at boot); the os.Stderr fallback exists so unit
// tests constructing Store directly keep working.
func (s *Store) fireListeners(ctx context.Context, row PersistedEvent) {
	// Snapshot under RLock so the dispatch loop runs without holding
	// the mutex (listeners may take milliseconds; we don't want to
	// block concurrent RegisterEventListener calls or other readers
	// for that long). Slice header copy is safe because
	// RegisterEventListener appends — never mutates an existing
	// element. Logger is snapshotted under the same lock so a
	// concurrent SetLogger doesn't race with the panic-recovery read
	// inside the closure below.
	s.listenersMu.RLock()
	onEvent := s.OnEventAppended
	listeners := s.listeners
	logger := s.logger
	s.listenersMu.RUnlock()

	safe := func(name string, fn func()) {
		defer func() {
			if r := recover(); r != nil {
				if logger != nil {
					logger.Error("store: listener panicked",
						"listener", name,
						"stream_type", row.StreamType,
						"event_type", row.EventType,
						"panic", r)
				} else {
					fmt.Fprintf(os.Stderr, "store: %s listener panicked on %s/%s: %v\n", name, row.StreamType, row.EventType, r)
				}
			}
		}()
		fn()
	}

	if onEvent != nil {
		safe("OnEventAppended", func() { onEvent(ctx, row) })
	}
	for _, l := range listeners {
		safe("RegisterEventListener", func() { l(ctx, row) })
	}
}

// New creates a new Store and runs migrations.
// This should only be called by the control server which is responsible for database schema management.
func New(ctx context.Context, connString string) (*Store, error) {
	// Create connection pool
	pool, err := pgxpool.New(ctx, connString)
	if err != nil {
		return nil, fmt.Errorf("create connection pool: %w", err)
	}

	// Verify connection
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}

	// Run migrations using a standard database/sql connection
	// Goose doesn't support pgx directly, so we use the stdlib adapter
	sqlDB, err := sql.Open("pgx", connString)
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("open database for migrations: %w", err)
	}
	defer sqlDB.Close()

	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("postgres"); err != nil {
		pool.Close()
		return nil, fmt.Errorf("set goose dialect: %w", err)
	}
	if err := goose.Up(sqlDB, "."); err != nil {
		pool.Close()
		return nil, fmt.Errorf("run migrations: %w", err)
	}

	return &Store{
		pool:    pool,
		queries: generated.New(pool),
	}, nil
}

// NewWithoutMigrations creates a new Store without running migrations.
// This should be used by services that only consume the database (e.g., gateway)
// and don't manage the schema.
func NewWithoutMigrations(ctx context.Context, connString string) (*Store, error) {
	// Create connection pool
	pool, err := pgxpool.New(ctx, connString)
	if err != nil {
		return nil, fmt.Errorf("create connection pool: %w", err)
	}

	// Verify connection
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}

	return &Store{
		pool:    pool,
		queries: generated.New(pool),
	}, nil
}

// Queries returns the SQLC queries interface.
func (s *Store) Queries() *Queries {
	return s.queries
}

// Pool returns the underlying connection pool.
func (s *Store) Pool() *pgxpool.Pool {
	return s.pool
}

// Close closes the database connection.
func (s *Store) Close() {
	s.pool.Close()
}

// WithTx runs a function within a transaction.
func (s *Store) WithTx(ctx context.Context, fn func(*Queries) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	if err := fn(s.queries.WithTx(tx)); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}

	return nil
}

// AppendEvent appends a new event to the event store.
// It auto-determines the stream version with optimistic retry on conflicts.
func (s *Store) AppendEvent(ctx context.Context, event Event) error {
	if event.ActorType == "" || event.ActorID == "" {
		return fmt.Errorf("event actor_type and actor_id are required")
	}

	data, err := json.Marshal(event.Data)
	if err != nil {
		return fmt.Errorf("marshal event data: %w", err)
	}

	metadata := []byte("{}")
	if event.Metadata != nil {
		metadata, err = json.Marshal(event.Metadata)
		if err != nil {
			return fmt.Errorf("marshal event metadata: %w", err)
		}
	}

	const maxRetries = 5
	for i := 0; i < maxRetries; i++ {
		version, err := s.queries.GetStreamVersion(ctx, generated.GetStreamVersionParams{
			StreamType: event.StreamType,
			StreamID:   event.StreamID,
		})
		if err != nil {
			return fmt.Errorf("get stream version: %w", err)
		}

		row, err := s.queries.AppendEvent(ctx, generated.AppendEventParams{
			StreamType:    event.StreamType,
			StreamID:      event.StreamID,
			StreamVersion: version + 1,
			EventType:     event.EventType,
			Data:          data,
			Metadata:      metadata,
			ActorType:     event.ActorType,
			ActorID:       event.ActorID,
		})
		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				if i < maxRetries-1 {
					continue // Retry on version conflict
				}
				return fmt.Errorf("version conflict after %d retries: stream was modified concurrently", maxRetries)
			}
			return fmt.Errorf("append event: %w", err)
		}
		s.fireListeners(ctx, row)
		return nil
	}
	return fmt.Errorf("append event: exhausted retries")
}

// AppendEventWithVersion appends an event with an expected version for optimistic locking.
func (s *Store) AppendEventWithVersion(ctx context.Context, event Event, expectedVersion int32) error {
	data, err := json.Marshal(event.Data)
	if err != nil {
		return fmt.Errorf("marshal event data: %w", err)
	}

	metadata := []byte("{}")
	if event.Metadata != nil {
		metadata, err = json.Marshal(event.Metadata)
		if err != nil {
			return fmt.Errorf("marshal event metadata: %w", err)
		}
	}

	row, err := s.queries.AppendEvent(ctx, generated.AppendEventParams{
		StreamType:    event.StreamType,
		StreamID:      event.StreamID,
		StreamVersion: expectedVersion,
		EventType:     event.EventType,
		Data:          data,
		Metadata:      metadata,
		ActorType:     event.ActorType,
		ActorID:       event.ActorID,
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return fmt.Errorf("version conflict: expected version %d but stream was modified", expectedVersion)
		}
		return fmt.Errorf("append event: %w", err)
	}
	s.fireListeners(ctx, row)

	return nil
}
