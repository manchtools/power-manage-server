# ADR 0027: Search rebuild uses load-then-index (not stream-into-live-index)

Status: Accepted
Date: 2026-06-27

## Context

The search indexer (`server/internal/search`) builds the FT search indexes from
the Postgres projections. The cutover from RediSearch (redis-stack) to
valkey-search (`valkey/valkey-bundle`) — see #319 — kept the original rebuild
order:

1. `FlushSearchData` — drop the FT indexes and the search keyspace,
2. `EnsureIndexes` — `FT.CREATE` all indexes (now LIVE),
3. `Warm` — bulk-pipeline an `HSET` per row into the now-live indexes.

On a real deployment this **deadlocked the indexer on startup**: the warm of the
`executions` scope (and any other scope with more than a few dozen rows) stalled
for ~120s and failed with `warm executions: pipeline exec: i/o timeout`, then the
indexer crash-looped / left search empty.

### Root cause (empirically established)

RediSearch indexed **synchronously** on the command, so streaming a bulk pipeline
of `HSET`s at a live index was fine. valkey-search introduced an **asynchronous
writer** (a small worker pool draining a mutation queue), and it applies
**synchronous backpressure**: when the mutation queue passes its high-water mark
the module stops replying to the writing command until the queue drains. The
writer only makes progress when the main thread returns to the event loop, so a
tight, un-flushed go-redis pipeline (which writes every command before reading
any reply) starves the writer and **deadlocks** — the client blocks on a reply
that never comes until its read timeout.

This was isolated to the engine, not our data or driver:

- Same valkey-bundle, same go-redis, same 151-HSET pipeline: into **FT-indexed**
  keys it wedged at ~120s; into **un-indexed** keys it returned in **1 ms**.
- Writing only the 6 indexed schema fields (no extra fields) still wedged → not a
  data/field/type problem.
- One-`HSET`-at-a-time (the live incremental path) completed every row → the
  engine indexes our data fine; only the bulk firehose into a live index breaks.
- Writing the keyspace **first** and creating the index **after** indexed **3020
  rows in ~110 ms** (valkey-search backfills by scanning at its own pace).

The live/incremental path (`internal/search/worker.go`, one `HSET` per event) was
never affected — only the bulk `Warm`/`Rebuild` and the boot "re-warm into a
present index" path.

## Decision

**Rebuild loads data, then indexes it.** `Index.Rebuild` is reordered to:

1. `FlushSearchData`,
2. `Warm` — write every search hash into the **index-less** keyspace (fast, no
   writer backpressure),
3. `EnsureIndexes` — `FT.CREATE`, which backfills the populated keyspace in the
   background,
4. `waitForBackfill` — poll `FT.INFO backfill_in_progress` until every index is
   done, so a completed `Rebuild` guarantees a query-ready index.

**The boot gate no longer re-warms a live index.** `startupSearchSync`
(`cmd/indexer/rebuild_gate.go`) previously called `Warm` on a normal restart
(indexes present + schema current) and on lock contention — both stream a full
reload of `HSET`s into a live index and would deadlock at scale. Both now **skip**
the bulk reload: the data is already indexed, the incremental worker keeps it
live, and the periodic reconcile (`Rebuild`) corrects drift. The destructive
load-then-index rebuild still runs only when indexes are missing or the schema
fingerprint changed, under the single-writer lock (WS13 #12 is preserved).

## Consequences

- A big deployment warms on startup at any scale (regression test seeds 5000
  executions and asserts `Rebuild` completes under a bounded context with every
  row indexed).
- During a rebuild the indexes are briefly absent (between flush and
  `EnsureIndexes`) instead of present-but-partial; for a boot/reconcile this is an
  acceptable, short, search-unavailable window rather than a deadlock.
- No magic batch size and no engine change. Reverting to RediSearch (source-
  available licensing; the single valkey-bundle also backs the Asynq queue) was
  considered and rejected — the defect is a contained client-side ordering bug,
  not an engine deficiency.
- Upgrading in place from a wedged rc4 (indexes present, schema "current",
  executions empty) self-heals on the next periodic reconcile; a fresh deploy
  (indexes missing) is correct immediately.
