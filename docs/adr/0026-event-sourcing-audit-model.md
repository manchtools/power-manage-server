# 0026 — Event sourcing & audit model: append-only events, derived projections, synchronous Go projectors

- Status: accepted
- Date: 2026-06-26
- Related: #324 (foundational ADR backfill). The substrate that ADR 0004
  (event representation is proto-native), 0005 (append-only events trigger), 0020
  (fail-closed error discipline), 0021 (`decodePayload` single-source), 0023, and
  0024 (event-driven dynamic membership) all rely on. Cross-referenced from
  `SECURITY.md`.

## Context

Power Manage is CQRS/event-sourced: every state change is recorded as an
immutable event, and all reads come from derived projections. This is what gives
the system a complete audit trail, tamper-evident history, and the ability to
rebuild read state. The foundational rules — who may write what, how projections
stay consistent, and how the audit path avoids leaking secrets — were established
incrementally across the storage-abstraction and security-hardening work but never
captured in one place.

## Decision

- **The `events` table is the single source of truth; `*_projection` tables are
  derived read models.** Queries read projections, never the event store. A
  request handler **appends an event**; it does not write a projection directly.

- **Events are append-only at the database layer.** A trigger (migration 011,
  ADR 0005) blocks `UPDATE`/`DELETE` on `events`, so history is immutable even
  against a bug or a direct SQL path — not merely by convention.

- **Projections are maintained by Go projector listeners** (`internal/projectors`),
  registered on the store and fired **synchronously, in registration order**,
  inside `AppendEvent`'s `fireListeners` loop. Ordering is load-bearing: e.g. the
  device-group projector applies dynamic membership *before* the search listener
  reindexes the affected entities (ADR 0024). Listeners swallow+log their own
  errors (post-commit contract); the periodic reconcile / `RebuildAll` is the
  safety net for a dropped projection write.

- **`RebuildAll` re-derives every projection by replaying events** through the
  same `Apply*` functions the live listeners use — so a projection can always be
  reconstructed from the log, and a new projection backfills correctly.

- **Asymmetric-guard discipline for multi-write events.** The version-guarded
  parent `UPDATE` (`:execrows`, bumping `projection_version`) runs *first*; when it
  affects zero rows (a stale replay) the cascading child INSERT/DELETE is skipped.
  This is what stops a re-applied stale event from resurrecting removed rows or
  drifting a denormalized count.

- **Derived read-models that are NOT event-sourced are explicitly allowlisted and
  fitness-guarded.** A few engines own computed columns (compliance evaluation,
  etc.). `internal/archtest/projection_writes_test.go` AST-scans the tree and fails
  the build if any non-projector path writes a `*_projection` table without a
  justified allowlist entry — the CQRS write boundary is enforced mechanically, not
  by review.

- **Audit is derived from the event stream and redacts secrets.** Every
  state-changing RPC is audit-logged; the audit read path strips sensitive payload
  fields (e.g. `scim_token_hash` never surfaces through `ListAuditEvents`), pinned
  by a self-discovering payload guard (WS11).

## Consequences

- Complete, tamper-evident audit trail and full projection rebuildability fall out
  of the model rather than being bolted on.
- Projections are *eventually* consistent with the log on listener failure; the
  reconcile/rebuild path bounds the drift. Code that needs strict freshness must
  account for this (documented per handler).
- The write boundary ("handlers append events; projectors write projections") is a
  build-enforced invariant, so a future handler cannot silently bypass the event
  store.

## Alternatives considered

- **Mutable state in place (CRUD)** — rejected: no inherent audit trail, no
  rebuild, no tamper-evidence.
- **PL/pgSQL trigger-based projections** (the original approach) — migrated to Go
  projectors (#125/#136) for testability and rebuild parity; the DB trigger is now
  reserved for the append-only *invariant*, not projection logic.
- **Synchronous projection writes from the handler** — rejected: couples the write
  path to every read model and loses the replay/rebuild property.
