# 0029 — All Postgres state is event-sourced or explicitly classified

- Status: accepted
- Date: 2026-07-03
- Related: manchtools/power-manage-server#495 (guard family + lps_keypair
  event-sourcing); #496 (mutating RPCs with no audit event); #497 (replay
  gaps); ADR 0026 (event-sourcing audit model); ADR 0028 (LPS sealed
  transport — amended by this ADR); ADR 0009 (AES-GCM AAD at rest).

## Context

The event store is both the system of record and the audit log ("every
state-changing RPC is audit-logged" — the events table IS the audit log), and
the replay guarantee — drop derived state, replay events, get the same state
back — is what makes emergency rebuilds and disaster recovery trustworthy.

An audit for #495 found the guarantee held *by convention, not by
enforcement*:

- `lps_keypair` (#483 / ADR 0028) was written directly — advisory lock plus
  `INSERT … ON CONFLICT DO NOTHING` — the one Postgres row with no event
  behind it.
- Handler-level direct writes (generated queries, repo write methods) were
  unguarded; nothing failed the build when a mutation bypassed
  `AppendEvent`.
- Table-level coverage was unstated: which tables replay reproduces, which
  are deliberately operational, and which silently fell in between was
  nowhere recorded — and several fell in between (#497).

## Decision

**Contract.** All Postgres state is event-sourced or explicitly classified.
Concretely, every base table is exactly one of:

1. the event store itself (`events`) or migration bookkeeping
   (`goose_db_version`);
2. a projection covered by a rebuild target (`store.AllRebuildTargets`) —
   replay reproduces it 1:1;
3. a cascade-rederived child of a rebuild target — mechanically verified
   against the live FK graph, re-derived by the replayed streams;
4. registered operational state — by-design non-event-sourced (flow rows,
   staging rows, denylists, liveness inventories), each entry justifying why
   it lives in Postgres;
5. a **tracked replay gap** (#497) — never a silent exception.

Valkey state (search index, terminal token store, CRL cache, queues) is
ephemeral/rebuildable **by contract**: it may always be re-derived from
Postgres or re-established by reconnection, and is therefore out of the
replay guarantee's scope. `RebuildSearchIndex` re-deriving the FT index is
the canonical example, and remains the lone sanctioned "mutating RPC with no
event".

**lps_keypair joins the contract.** The keypair is now sourced from a
singleton `lps_keypair/global` stream:

- `EnsureLpsKeypair` appends `LpsKeypairGenerated` at stream version 1; the
  `UNIQUE(stream_type, stream_id, stream_version)` constraint IS the
  cross-replica first-writer-wins, replacing the advisory lock. A losing
  replica adopts the winner's keypair from the stream (not the projection
  row, closing the post-commit listener window).
- The `lps_keypair` table is a projection (`projectors.LpsKeypairListener`,
  rebuild target `lps_keypair`).
- The event payload carries the public key and the **enc:v2-encrypted**
  private key — encrypted-secret-in-payload is the established at-rest model
  (LPS rotations, TOTP secrets, IdP client secrets already ride encrypted in
  events; ADR 0009). The signed public key agents receive is byte-identical
  across the migration: same bytes, same AAD context, same signature input.
- Upgrade: a pre-#495 row without a stream gets a synthetic
  `LpsKeypairGenerated` backfilled (boot-time Go, not migration SQL — the
  payload is produced by the same Go struct the projector decodes, so the
  wire shape cannot drift, and the OCC append keeps concurrent replicas
  idempotent).

**Enforcement.** The contract is mechanical, not prose:

- `internal/api/event_append_completeness_test.go` — every mutating
  ControlService RPC must reach `AppendEvent`/`AppendEventWithVersion`
  (self-discovering over the RPC surface); no handler file may perform
  direct store writes outside an allowlisted, justified site.
- `internal/store/schema_classification_test.go` — every live table must
  classify into the five buckets above; registries are stale-checked and
  cross-checked against the live FK graph; the test red-verifies itself with
  an unclassified probe table each run.

## Alternatives considered

- **Allowlist lps_keypair in the guard.** Rejected — the single exception is
  exactly how replay guarantees rot; fixing it was cheaper than defending
  the exception forever.
- **Migration-SQL backfill.** Rejected in favour of boot-time Go: SQL would
  re-encode the payload shape by hand (jsonb_build_object + base64) and
  silently drift from the Go decoder; the Go path reuses the one payload
  struct end-to-end.
- **Keep the advisory lock alongside the OCC append.** Rejected — the
  version-1 uniqueness already serializes winners; a second mechanism just
  hides which one is load-bearing.

## Consequences

- The guard family makes new bypasses unmergeable: a new mutating RPC
  without an event, a new direct write, or a new unclassified table each
  fail a test with a targeted message.
- Known debts are explicit and tracked: six RPCs mutate without events
  (#496); several projections are not replay-covered, two of which a users
  rebuild actively destroys today (#497). Fixing one forces its registry
  entry's removal — the registries can only shrink honestly.
- `InsertLpsKeypair` is gone from the generated query set; the projector
  owns the only write (`UpsertLpsKeypair`).
