// Package store provides database access for the control server.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib" // pgx database/sql driver
	"github.com/oklog/ulid/v2"
	"github.com/pressly/goose/v3"

	"github.com/manchtools/power-manage/server/internal/crypto"
	"github.com/manchtools/power-manage/server/internal/store/generated"
	"github.com/manchtools/power-manage/server/internal/store/migrations"
)

// Re-export generated types for convenience
type Queries = generated.Queries
type PersistedEvent = generated.Event

// Event represents a domain event.
//
// Data accepts any JSON-marshalable value. Prefer a typed payload
// struct from internal/eventtypes/payloads — sharing one struct between
// the handler emit site and the projector decoder catches schema drift
// at compile time. The legacy map[string]any literal remains supported
// for not-yet-converted call sites; AppendEvent json.Marshals whatever
// is passed, so the wire format is unchanged.
type Event struct {
	StreamType string
	StreamID   string
	EventType  string
	Data       any
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
// Wired in projectors.WireAll for every Go-ported projector that owns
// an entry in AllRebuildTargets. Every rebuild target MUST have a
// registered applier: RebuildAll hard-errors on a target with none (the
// PL/pgSQL projector dispatch was dropped in migration 041), so a
// drifted WireAll wiring fails loudly instead of silently no-op'ing.
//
// Refs manchtools/power-manage-server#125.
type RebuildApply func(ctx context.Context, q *Queries, ev PersistedEvent) error

// Store wraps the database connection and provides access to queries.
type Store struct {
	now     func() time.Time // clock seam; defaults to time.Now, overridden in tests
	pool    *pgxpool.Pool
	queries *Queries

	// advisoryMu serializes LOCAL goroutines competing for an advisory lock
	// BEFORE they acquire a pooled connection (see WithAdvisoryLock). Without
	// it, N concurrent callers each grab a conn and block on pg_advisory_lock,
	// so when N >= pool size the lock-holder's callback can't get the extra
	// conns it needs and the whole set deadlocks (this kept the api CI shard at
	// its 30m timeout). One mutex is correct for the current single advisory
	// key; switch to a per-key map if a second hot key is added.
	advisoryMu sync.Mutex

	// listenersMu guards listeners + rebuildAppliers. Documented usage
	// is "register at boot, then start serving", but Go's race detector
	// won't catch a future caller that registers after AppendEvent is in
	// flight (concurrent slice append + range read is a data race).
	// RWMutex is cheap on the hot read path (fireListeners holds RLock)
	// and lets boot code register without extra ceremony.
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

	// logger is used by fireListeners to log panic recoveries through
	// the standard logging pipeline instead of os.Stderr. Optional;
	// when nil, falls back to os.Stderr so unit tests that construct
	// a Store directly don't require log plumbing. Set via SetLogger
	// from cmd/{control,indexer}/main.go after construction.
	logger *slog.Logger

	// repos is the domain repository registry. Wired via SetRepos
	// from boot code (cmd/control, cmd/indexer, test fixture) AFTER
	// store.New returns and BEFORE any handler runs. Guarded by
	// listenersMu — same boot-once-then-read posture as listeners +
	// rebuildAppliers + logger. Read via Store.Repos(), which panics
	// if SetRepos was never called so misconfiguration fails loudly
	// instead of nil-derefing deep inside a handler.
	//
	// Part of the storage-abstraction tracker (#242). Domains move
	// from Store.Queries() into Repos fields one wave at a time.
	repos *Repos

	// piiSealer, when set, transforms every event BEFORE its payload is
	// marshalled: PII-tagged fields are sealed under the subject user's
	// DEK (spec 19 / ADR 0030). FAIL-CLOSED contract (AC 6): a sealing
	// error aborts the append — the log is immutable, so plaintext PII
	// written once is unerasable forever; an error is always cheaper.
	// Wired via SetPIISealer from boot code / the test fixture,
	// boot-once posture like logger/repos.
	piiSealer PIISealer

	// piiMinter mints per-user DEKs at creation (spec 19 AC 1). Wired
	// via SetPIIMinter alongside the sealer.
	piiMinter PIIMinter

	// beforeInsert, when non-nil, is consulted in appendOne before each
	// event insert — so it fires for BOTH AppendEvent and AppendEvents
	// (they share appendOne). A non-nil return aborts that insert,
	// letting a test drive the all-or-nothing rollback (spec 28 AC 2),
	// the whole-batch retry (return ErrVersionConflict → AC 5), and the
	// SCIM orphan regression (AC 8) deterministically. TEST-ONLY, set via
	// TestingSetInsertHook; always nil in production, so the per-insert
	// nil check is the only cost the write path pays.
	beforeInsert func(streamType, eventType string) error

	// beforeDEKShred, when non-nil, is consulted in
	// AppendUserDeletionWithShred AFTER the UserDeleted append but BEFORE
	// the DEK delete, so a test can fail the shred step specifically and
	// assert the already-appended UserDeleted rolls back (spec 19 AC 14).
	// TEST-ONLY, set via TestingSetDEKShredHook; always nil in production.
	beforeDEKShred func(userID string) error
}

// PIISealer seals the PII fields of an event's typed payload under the
// subject user's DEK. Implemented by internal/pii.Sealer; a nil-safe
// no-op when unset (bootstrap paths that predate the wiring).
type PIISealer interface {
	SealEvent(ctx context.Context, e Event) (Event, error)
}

// PIIMinter mints a user's DEK at creation time (spec 19 AC 1).
// Implemented by internal/pii.Minter; exposed through the Store so
// every user-provisioning path (API handler, SCIM, SSO linker,
// bootstrap) can mint without new constructor plumbing.
type PIIMinter interface {
	MintUserDEK(ctx context.Context, userID string) error
}

// SetPIIMinter wires the DEK minter. Boot-once posture matching
// SetPIISealer.
func (s *Store) SetPIIMinter(m PIIMinter) {
	s.listenersMu.Lock()
	s.piiMinter = m
	s.listenersMu.Unlock()
}

// MintUserDEK mints the DEK for a newly created user. FAIL-CLOSED when
// no minter is wired: a creation path proceeding without a key would
// immediately hit the sealer's fail-closed append anyway — erroring
// here names the real problem.
func (s *Store) MintUserDEK(ctx context.Context, userID string) error {
	s.listenersMu.RLock()
	m := s.piiMinter
	s.listenersMu.RUnlock()
	if m == nil {
		return fmt.Errorf("store: no PII minter wired (SetPIIMinter at boot) — cannot provision user %s", userID)
	}
	return m.MintUserDEK(ctx, userID)
}

// SetPIISealer wires the PII envelope sealer (spec 19). Boot-once
// posture matching SetRepos/SetLogger.
func (s *Store) SetPIISealer(p PIISealer) {
	s.listenersMu.Lock()
	s.piiSealer = p
	s.listenersMu.Unlock()
}

// sealPII applies the wired sealer to an event, or returns it
// unchanged when no sealer is wired.
func (s *Store) sealPII(ctx context.Context, e Event) (Event, error) {
	s.listenersMu.RLock()
	sealer := s.piiSealer
	s.listenersMu.RUnlock()
	if sealer == nil {
		// Fail CLOSED (spec 29 S9): a nil sealer must never let PII-tagged fields
		// reach the append-only log as plaintext — the log is immutable, so a
		// single plaintext PII write is unerasable forever. A non-PII event passes
		// (bootstrap paths that predate the wiring, low-level store tests); an
		// event carrying PII-tagged fields with no sealer is refused. Symmetric
		// with MintUserDEK, closing the sealer/minter asymmetry.
		if e.Data != nil && len(crypto.PIIFieldNames(e.Data)) > 0 {
			return Event{}, fmt.Errorf("store: refusing to append PII event %q with no PII sealer wired (call SetPIISealer at boot)", e.EventType)
		}
		return e, nil
	}
	return sealer.SealEvent(ctx, e)
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

// HasRebuildApply reports whether a Go applier is registered for the named
// rebuild target. Exposed so a parity test can assert every AllRebuildTargets
// entry is wired (a missing applier makes RebuildAll silently no-op the
// projection — the failure mode #125 fixed).
func (s *Store) HasRebuildApply(name string) bool {
	s.listenersMu.RLock()
	defer s.listenersMu.RUnlock()
	_, ok := s.rebuildAppliers[name]
	return ok
}

// fireListeners invokes every RegisterEventListener entry. Centralised
// so the two AppendEvent variants stay in sync.
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
	// for that long).
	//
	// Slice-header copy of s.listeners is safe because
	// RegisterEventListener uses append-only semantics: when it
	// grows the backing array, Go allocates a NEW array and binds
	// it to the new header, leaving the old array (which our
	// snapshot still references) untouched. We never mutate an
	// existing element in place. Concurrent writers can therefore
	// continue to extend the canonical slice while this dispatch
	// loop iterates the frozen snapshot. Audit F038.
	//
	// Logger is snapshotted under the same lock so a concurrent
	// SetLogger doesn't race with the panic-recovery read inside
	// the closure below.
	s.listenersMu.RLock()
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

	for _, l := range listeners {
		safe("RegisterEventListener", func() { l(ctx, row) })
	}
}

// Pool tuning (WS13 #10). statementTimeout bounds any SINGLE query's wall-clock
// so a runaway/pathological statement cannot pin a connection indefinitely
// (it is per-statement, not per-transaction, so a long multi-statement replay is
// unaffected; migrations run on a separate stdlib connection and are exempt).
// MaxConns/MaxConnLifetime are set explicitly rather than left to pgx defaults.
const (
	statementTimeout    = 30 * time.Second
	poolMaxConns        = 20
	poolMaxConnLifetime = time.Hour
)

// newPool builds a tuned pgx pool: an application statement_timeout in the
// connection RuntimeParams plus explicit MaxConns/MaxConnLifetime. Shared by
// New and NewWithoutMigrations so control/gateway/indexer get the same bounds.
func newPool(ctx context.Context, connString string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(connString)
	if err != nil {
		return nil, fmt.Errorf("parse pool config: %w", err)
	}
	if cfg.ConnConfig.RuntimeParams == nil {
		cfg.ConnConfig.RuntimeParams = map[string]string{}
	}
	// Respect an operator-provided statement_timeout in the DSN; otherwise apply
	// our default. Postgres takes a bare integer as milliseconds.
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

// New creates a new Store and runs migrations.
// This should only be called by the control server which is responsible for database schema management.
func New(ctx context.Context, connString string) (*Store, error) {
	// Create connection pool
	pool, err := newPool(ctx, connString)
	if err != nil {
		return nil, err
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
		now:     time.Now,
		pool:    pool,
		queries: generated.New(pool),
	}, nil
}

// NewWithoutMigrations creates a new Store without running migrations.
// This should be used by services that only consume the database (e.g., gateway)
// and don't manage the schema.
func NewWithoutMigrations(ctx context.Context, connString string) (*Store, error) {
	// Create connection pool
	pool, err := newPool(ctx, connString)
	if err != nil {
		return nil, err
	}

	// Verify connection
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}

	return &Store{
		now:     time.Now,
		pool:    pool,
		queries: generated.New(pool),
	}, nil
}

// Queries returns the SQLC queries interface.
//
// Transitional: new handler code should depend on Store.Repos() and
// the domain interfaces in this package. Queries() remains exported
// during the storage-abstraction migration (#242) for handlers whose
// domain has not yet been ported to a repository. Each Wave B.N
// sub-PR shrinks the set of remaining callers; Queries() goes
// private once the last one migrates.
//
// Intentionally NOT marked with the godoc "Deprecated:" keyword —
// every existing caller is part of the planned migration set, not
// an unsanctioned use, so flagging them via staticcheck SA1019 would
// just add ceremony (//lint:ignore tags) without changing behaviour.
// The marker re-enters the moment Queries() goes unexported.
func (s *Store) Queries() *Queries {
	return s.queries
}

// SetRepos wires the domain repository registry. Called once after
// store.New / NewWithoutMigrations by boot code in cmd/control,
// cmd/indexer, or the test fixture (internal/testutil). Handlers
// reach the registry via Store.Repos().
//
// Boot code typically calls:
//
//	st, _ := store.New(ctx, dsn)
//	st.SetRepos(postgres.NewRepos(st.Queries()))
//
// Splitting this out of store.New keeps the store package free of
// any backend-specific import — postgres is wired by the binary,
// not by the abstraction it implements.
func (s *Store) SetRepos(r *Repos) {
	s.listenersMu.Lock()
	s.repos = r
	s.listenersMu.Unlock()
}

// Repos returns the domain repository registry. Panics if SetRepos
// was never called — every Store construction site MUST wire repos
// before handlers start serving traffic, so a missing wire is a
// boot-time misconfiguration that should fail loudly.
func (s *Store) Repos() *Repos {
	s.listenersMu.RLock()
	r := s.repos
	s.listenersMu.RUnlock()
	if r == nil {
		panic("store: Repos accessed before SetRepos — wire postgres.NewRepos in your boot code (see #242)")
	}
	return r
}

// TestingPool returns the underlying pgx connection pool for test
// fixtures that need to issue raw SQL outside the repo abstraction
// (projector applies, schema introspection, raw-row asserts). Production
// code must not call this — every backend swap on the storage-abstraction
// tracker (#242) would have to re-implement this method, so reaching for
// it is by definition backend-specific. New tests should prefer
// Store.Queries() / Store.Repos() and add a query if one is missing.
//
// The name is deliberately backend-flavoured to make new misuse easy to
// grep for and to keep the "this couples me to Postgres" signal visible.
func (s *Store) TestingPool() *pgxpool.Pool {
	return s.pool
}

// Close closes the database connection.
func (s *Store) Close() {
	s.pool.Close()
}

// LoadStream satisfies EventStore.LoadStream. Thin wrapper over the
// sqlc-generated LoadStream query; lifts the (stream_type, stream_id)
// → []PersistedEvent shape onto Store so callers can depend on the
// EventStore interface instead of reaching into Queries().
func (s *Store) LoadStream(ctx context.Context, streamType, streamID string) ([]PersistedEvent, error) {
	return s.queries.LoadStream(ctx, generated.LoadStreamParams{
		StreamType: streamType,
		StreamID:   streamID,
	})
}

// LoadStreamByType satisfies EventStore.LoadStreamByType. Pages over
// every event with the given stream_type ordered by sequence_num
// descending. Mirrors the existing LoadEventsByStreamType query the
// audit-log + reconciler callers used directly.
func (s *Store) LoadStreamByType(ctx context.Context, streamType string, limit, offset int32) ([]PersistedEvent, error) {
	return s.queries.LoadEventsByStreamType(ctx, generated.LoadEventsByStreamTypeParams{
		StreamType: streamType,
		Limit:      limit,
		Offset:     offset,
	})
}

// WithAdvisoryLock runs fn while holding a session-level PostgreSQL advisory
// lock on key, serializing every caller that uses the same key on this
// database. The lock is held across the ENTIRE fn — including any synchronous
// post-commit projector writes triggered by an AppendEvent inside fn — so a
// read-side guard that checks a projection and then appends an event is atomic
// against a concurrent caller: the next caller blocks until this one's
// projection write has landed, rather than racing on a stale read.
//
// The lock is taken on a dedicated pooled connection and explicitly released
// (a pooled connection is not closed on Release, so a session lock would
// otherwise leak). The release is detached from ctx so a cancelled request
// still frees the lock, and surfaces as the returned error only when fn itself
// succeeded.
func (s *Store) WithAdvisoryLock(ctx context.Context, key int64, fn func() error) (err error) {
	// Serialize local goroutines BEFORE taking a pooled connection. Otherwise N
	// concurrent callers each acquire a conn and block on pg_advisory_lock
	// below; once N reaches the pool size, the one goroutine that won the lock
	// can't acquire the additional conns its fn() needs (guard reads + append),
	// and the whole set deadlocks. With the mutex, waiters hold NO connection
	// while they queue, so the lock-holder always has the rest of the pool. The
	// pg_advisory_lock still serializes across PROCESSES (HA / multi-instance).
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

// TryWithAdvisoryLock is the non-blocking sibling of WithAdvisoryLock. It runs
// fn while holding a session-level advisory lock on key ONLY IF the lock is free
// across the whole database; if another session already holds it (e.g. another
// control replica), it reports ran=false WITHOUT running fn. Used by the
// dynamic-group drain so two replicas never evaluate the same group concurrently
// — the second skips it and the queue row it leaves behind is picked up later
// (at-least-once; evaluation is idempotent).
//
// Same local-mutex discipline as WithAdvisoryLock: the mutex is taken only for
// the brief try (and across fn when acquired) so a skipping caller releases it
// immediately. Cross-process exclusion is pg_try_advisory_lock's job — within a
// single process the mutex already serializes callers, so the skip path matters
// across replicas (the actual concern).
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

// preparedEvent is an Event after validation, PII sealing, and JSON
// marshalling — everything that must happen BEFORE a write. Producing it
// once lets AppendEvent and AppendEvents share identical per-event
// preparation so the two paths cannot drift (spec 28). The ULID and
// stream_version are assigned per insert attempt in appendOne, not here,
// so a retry mints fresh values.
type preparedEvent struct {
	streamType string
	streamID   string
	eventType  string
	data       []byte
	metadata   []byte
	actorType  string
	actorID    string
}

// prepareEvent validates, seals PII (fail-closed), and marshals one
// event. Shared by AppendEvent and AppendEvents; for a batch it runs for
// every event BEFORE any transaction opens, so a validation or seal
// failure aborts with zero DB work and zero partial state (spec 28 AC
// 2/6; spec 19 fail-closed — plaintext PII must never reach the
// immutable log as a fallback).
func (s *Store) prepareEvent(ctx context.Context, event Event) (preparedEvent, error) {
	if event.ActorType == "" || event.ActorID == "" {
		return preparedEvent{}, fmt.Errorf("event actor_type and actor_id are required")
	}

	event, err := s.sealPII(ctx, event)
	if err != nil {
		return preparedEvent{}, fmt.Errorf("seal PII: %w", err)
	}

	data, err := json.Marshal(event.Data)
	if err != nil {
		return preparedEvent{}, fmt.Errorf("marshal event data: %w", err)
	}

	metadata := []byte("{}")
	if event.Metadata != nil {
		metadata, err = json.Marshal(event.Metadata)
		if err != nil {
			return preparedEvent{}, fmt.Errorf("marshal event metadata: %w", err)
		}
	}

	return preparedEvent{
		streamType: event.StreamType,
		streamID:   event.StreamID,
		eventType:  event.EventType,
		data:       data,
		metadata:   metadata,
		actorType:  event.ActorType,
		actorID:    event.ActorID,
	}, nil
}

// appendOne reads the current stream version and inserts pe at
// version+1 using q. q may be pool-bound (AppendEvent: each insert
// auto-commits, and a retry re-reads the committed version) or tx-bound
// (AppendEvents: all inserts share one transaction, so an earlier
// same-stream insert in the same batch is visible to this read —
// read-your-writes — giving consecutive versions, spec 28 AC 3). A
// unique-violation on (stream_type, stream_id, stream_version) surfaces
// as a version conflict (IsVersionConflict) for the caller's retry
// policy. Returns the inserted row for post-commit listener dispatch.
func (s *Store) appendOne(ctx context.Context, q *Queries, pe preparedEvent) (PersistedEvent, error) {
	// Test-only failure seam (spec 28 AC 2/5/8): nil in production.
	if s.beforeInsert != nil {
		if err := s.beforeInsert(pe.streamType, pe.eventType); err != nil {
			return PersistedEvent{}, err
		}
	}

	version, err := q.GetStreamVersion(ctx, generated.GetStreamVersionParams{
		StreamType: pe.streamType,
		StreamID:   pe.streamID,
	})
	if err != nil {
		return PersistedEvent{}, fmt.Errorf("get stream version: %w", err)
	}

	row, err := q.AppendEvent(ctx, generated.AppendEventParams{
		ID:            ulid.Make().String(),
		StreamType:    pe.streamType,
		StreamID:      pe.streamID,
		StreamVersion: version + 1,
		EventType:     pe.eventType,
		Data:          pe.data,
		Metadata:      pe.metadata,
		ActorType:     pe.actorType,
		ActorID:       pe.actorID,
	})
	if err != nil {
		return PersistedEvent{}, err
	}
	return row, nil
}

// AppendEvent appends a new event to the event store.
// It auto-determines the stream version with optimistic retry on conflicts.
func (s *Store) AppendEvent(ctx context.Context, event Event) error {
	pe, err := s.prepareEvent(ctx, event)
	if err != nil {
		return err
	}

	const maxRetries = 5
	for i := 0; i < maxRetries; i++ {
		row, err := s.appendOne(ctx, s.queries, pe)
		if err != nil {
			if IsVersionConflict(err) {
				if i < maxRetries-1 {
					continue // Retry on version conflict
				}
				return fmt.Errorf("%w: stream was modified concurrently after %d retries", ErrVersionConflict, maxRetries)
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
	// Route through prepareEvent so this OCC path shares the SAME validation +
	// fail-closed PII seal + marshal as AppendEvent/AppendEvents — including the
	// actor_type/actor_id required check (spec 29 S8): all three append paths now
	// reject an unattributable event rather than only AppendEvent doing so.
	pe, err := s.prepareEvent(ctx, event)
	if err != nil {
		return err
	}

	// Test-only failure seam, consistent with appendOne.
	if s.beforeInsert != nil {
		if berr := s.beforeInsert(pe.streamType, pe.eventType); berr != nil {
			return berr
		}
	}

	row, err := s.queries.AppendEvent(ctx, generated.AppendEventParams{
		ID:            ulid.Make().String(),
		StreamType:    pe.streamType,
		StreamID:      pe.streamID,
		StreamVersion: expectedVersion,
		EventType:     pe.eventType,
		Data:          pe.data,
		Metadata:      pe.metadata,
		ActorType:     pe.actorType,
		ActorID:       pe.actorID,
	})
	if err != nil {
		if IsVersionConflict(err) {
			return fmt.Errorf("%w: expected version %d but stream was modified", ErrVersionConflict, expectedVersion)
		}
		return fmt.Errorf("append event: %w", err)
	}
	s.fireListeners(ctx, row)

	return nil
}

// AppendEvents commits a batch of events across one or more streams
// atomically — all of them land, or none do — and fires listeners only
// after the whole batch commits (spec 28). Use it for a logical action
// spanning several streams (e.g. SCIM group create → UserGroupCreated +
// SCIMGroupMapped + members), where independent AppendEvent calls can
// leave partial state if a later one fails.
//
// Semantics:
//   - An empty/nil batch is a no-op returning nil.
//   - Every event is validated, PII-sealed (fail-closed) and marshalled
//     BEFORE the transaction opens, so a bad event writes nothing.
//   - Events insert in array order; same-stream events get consecutive
//     versions (read-your-writes within the tx).
//   - A version conflict retries the WHOLE transaction (re-reading
//     versions) up to a bounded budget; on exhaustion it returns
//     ErrVersionConflict having written nothing.
//   - Listeners fire post-commit, once per event, in array order,
//     through the same panic-safe fireListeners AppendEvent uses — which
//     is the sole projection path now that PL/pgSQL projection is
//     retired, so a batched event projects identically to a singly
//     appended one.
func (s *Store) AppendEvents(ctx context.Context, events []Event) error {
	if len(events) == 0 {
		return nil
	}

	// Prepare (validate + seal + marshal) every event before opening the
	// transaction: a failure here means zero DB work and zero partial
	// state (spec 28 AC 2/6).
	prepared := make([]preparedEvent, len(events))
	for i, e := range events {
		pe, err := s.prepareEvent(ctx, e)
		if err != nil {
			return fmt.Errorf("append events: event %d: %w", i, err)
		}
		prepared[i] = pe
	}

	const maxRetries = 5
	for i := 0; i < maxRetries; i++ {
		rows, err := s.appendBatchTx(ctx, prepared)
		if err != nil {
			// A version conflict OR a deadlock aborts this transaction;
			// both are transient, so retry the WHOLE batch (fresh tx,
			// re-read versions). Reversed-order overlapping batches
			// deadlock (40P01) rather than unique-violate — retrying
			// resolves them the same way.
			if IsVersionConflict(err) || isDeadlock(err) {
				if i < maxRetries-1 {
					continue
				}
				return fmt.Errorf("%w: batch could not commit after %d retries (version conflict or deadlock)", ErrVersionConflict, maxRetries)
			}
			return fmt.Errorf("append events: %w", err)
		}
		// Post-commit: the batch is durable. Fire listeners per event in
		// array order — the sole projection path (spec 28 AC 4). A
		// panicking listener cannot fail the already-committed batch
		// (fireListeners' recover contract).
		for _, row := range rows {
			s.fireListeners(ctx, row)
		}
		return nil
	}
	return fmt.Errorf("append events: exhausted retries")
}

// appendBatchTx runs one all-or-nothing attempt: it opens a transaction,
// inserts every prepared event in order via the shared appendOne
// (tx-bound, so a same-stream read sees earlier inserts in this batch),
// commits, and returns the inserted rows for post-commit listener
// dispatch. Any error — version conflict or otherwise — returns before
// commit, so the deferred Rollback discards the whole batch and nothing
// is written.
func (s *Store) appendBatchTx(ctx context.Context, prepared []preparedEvent) ([]PersistedEvent, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	q := s.queries.WithTx(tx)
	rows := make([]PersistedEvent, len(prepared))
	for i, pe := range prepared {
		row, err := s.appendOne(ctx, q, pe)
		if err != nil {
			return nil, err
		}
		rows[i] = row
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit transaction: %w", err)
	}
	return rows, nil
}

// TestingSetInsertHook installs a test-only failure seam consulted
// before every event insert in AppendEvent / AppendEvents. Returning a
// non-nil error from fn aborts that insert; returning a
// version-conflict-classified error (store.ErrVersionConflict) drives
// the whole-batch retry. Lets tests exercise the all-or-nothing rollback
// (spec 28 AC 2), the retry/exhaust budget (AC 5), and the SCIM orphan
// regression (AC 8) deterministically, from any package, without a
// production failure flag. Pass nil to clear.
//
// Named like TestingPool: production code must not call this. It is
// exported only because the SCIM AC-8 regression test lives in another
// package and a concrete *Store gives it no other seam.
func (s *Store) TestingSetInsertHook(fn func(streamType, eventType string) error) {
	s.beforeInsert = fn
}

// TestingSetDEKShredHook installs a test-only failure seam consulted in
// AppendUserDeletionWithShred between the UserDeleted append and the DEK
// delete. Returning a non-nil error from fn fails the shred step, letting a
// test assert the all-or-nothing rollback (spec 19 AC 14): no UserDeleted
// event survives and the projection stays unredacted. Pass nil to clear.
// Same posture as TestingSetInsertHook — production code must not call this.
func (s *Store) TestingSetDEKShredHook(fn func(userID string) error) {
	s.beforeDEKShred = fn
}
