package store

import "context"

// EventStore is the abstract event-sourcing entry point that decouples
// handler-layer + projector-layer code from any particular database
// driver. Wave G of the storage-abstraction roadmap (tracker
// manchtools/power-manage-server#242).
//
// Postgres is the only impl shipped today (provided by *Store in this
// package). Future backends — SQL via different drivers (sqlite, libSQL,
// MySQL), document stores via conditional-write semantics — implement
// the same shape so handlers stay backend-agnostic.
//
// # Optimistic-concurrency contract
//
// AppendEvent computes the next stream_version inline and retries on
// constraint violation. AppendEventWithVersion takes a caller-supplied
// expected version and surfaces the conflict to the caller (no retry).
// On the Postgres impl both rely on the UNIQUE (stream_type, stream_id,
// stream_version) constraint to serialize concurrent writers; on
// NoSQL backends the same signature maps to conditional-write
// semantics ("write only if attribute X equals Y").
//
// # Listener contract
//
// RegisterEventListener registers a post-commit hook. On the Postgres
// impl the hook fires synchronously after AppendEvent returns success —
// listeners that need to outlive the request context derive their own
// (context.WithoutCancel + a timeout) before spawning async work.
//
// Cross-backend the contract is "best-effort post-commit notification."
// A backend that can't guarantee synchronous post-commit (eg. eventually
// consistent NoSQL) MUST document that listeners may be delayed and
// MUST NOT promise that a listener's side effects are observable by
// the time AppendEvent returns. The Postgres impl's synchronous
// guarantee is an upgrade, not a contract requirement.
//
// # Loading streams
//
// LoadStream returns every event for a (stream_type, stream_id) pair
// in stream_version order — the canonical replay path. LoadStreamByType
// pages over every event of a stream_type ordered by sequence_num
// descending; the limit / offset params mirror what the existing audit-
// log handlers used to call directly via Queries(). Callers that need
// finer-grained filtering (event_type, actor, time range) still go
// through the typed sqlc queries — those aren't in the interface
// because they're projection-shaped reads that don't map to NoSQL.
type EventStore interface {
	// AppendEvent writes a new event and fires registered listeners
	// on success. Auto-computes stream_version with retry-on-conflict
	// up to a small bound.
	AppendEvent(ctx context.Context, event Event) error

	// AppendEventWithVersion writes a new event only if the latest
	// event in the stream has expectedVersion. Returns a conflict
	// error otherwise — no retry.
	AppendEventWithVersion(ctx context.Context, event Event, expectedVersion int32) error

	// AppendEvents writes a batch of events across one or more streams
	// atomically (all land or none) and fires listeners once per event,
	// post-commit, in array order. The whole transaction is the retry
	// unit on a version conflict or deadlock. Use it for a logical
	// action that spans several streams; a single-element batch is
	// equivalent to AppendEvent.
	AppendEvents(ctx context.Context, events []Event) error

	// LoadStream returns every event for the given stream in
	// stream_version order. Used by rebuild paths and any consumer
	// that needs to replay a single aggregate's history.
	LoadStream(ctx context.Context, streamType, streamID string) ([]PersistedEvent, error)

	// LoadStreamByType pages over every event with the given
	// stream_type, ordered by sequence_num descending. The paging
	// shape matches the existing audit-log + reconciler call sites.
	LoadStreamByType(ctx context.Context, streamType string, limit, offset int32) ([]PersistedEvent, error)

	// RegisterEventListener installs a post-commit hook. Listeners
	// fire in registration order; see the package doc on
	// EventListener for failure / panic semantics.
	RegisterEventListener(fn EventListener)
}

// Compile-time guarantee that *Store satisfies EventStore. A future
// change that breaks the interface (rename, remove, change a
// signature) surfaces as a build failure here rather than at the
// first runtime callsite.
var _ EventStore = (*Store)(nil)
