# 0019 — Indexer startup rebuild: gate + lock instead of always-flush

- Status: accepted
- Date: 2026-06-15
- Related: WS13 #12 (manchtools/power-manage-server#427, split out of #426/#428);
  ADR 0018 (the rest of WS13's resource bounds); #319 (the now-merged deploy
  migration to valkey-search, whose testcontainer harness this ADR's
  integration test reuses).

## Context

The indexer ran a destructive `FlushSearchData` (FT.DROPINDEX + key SCAN/DEL)
followed by a full `Rebuild` on EVERY boot. A crash-loop, or several indexer
replicas starting together, could repeatedly wipe and rebuild the search index —
wasted work and a window where search returns nothing on each restart.

## Decision

Gate the destructive path behind an index-present check and a Valkey lock
(`cmd/indexer/rebuild_gate.go`, `startupSearchSync`):

- **Present check first.** `search.Index.IndexesPresent` runs `FT.INFO` for every
  configured index. If all exist, the indexer **warms without flushing** — a
  normal restart no longer drops the index. A present-check error is **fatal**
  (fail closed): guessing "missing" on a transient backend error would trigger an
  unwarranted destructive flush.
- **Lock the destructive path.** When indexes are missing, the indexer acquires a
  Valkey `SET NX EX` lock (`pm:indexer:rebuild:lock`, 15-min TTL, CAS-release)
  before `Rebuild`. A replica that loses the race **warms without flushing**, so
  concurrent/crash-looping indexers can't race repeated destructive wipes — at
  most one flushes.

This replaces the unconditional `EnsureIndexes` + `Rebuild` at boot (Rebuild
creates the indexes internally, so no separate ensure step is needed).

## Crash-loop protection ("backoff")

The original finding asked for "backoff so a crash-loop can't hammer destructive
rebuilds." The gate provides this structurally rather than via a timer: once a
rebuild succeeds the indexes are present, so every subsequent boot takes the
warm-without-flush path — the destructive flush happens at most once, not on every
restart. The lock bounds the pre-first-success window to a single flusher.

## Testing

The decision logic (`startupSearchSync`) is unit-tested with fakes
(present→warm; missing+lock-won→rebuild; missing+lock-lost→warm; present-check
error→fail-closed-no-flush). The Valkey lock (`valkeyRebuildLocker`) is tested
against miniredis (mutual exclusion + TTL + owner-only CAS-release). The real
`IndexesPresent` (`FT.INFO`) path is integration-tested against a real
valkey-search backend via the existing testcontainer harness
(`TestIndexesPresent`, valkey-bundle).

That integration test caught a real cold-start bug: valkey-search reports a
missing index as `Index with name 'X' not found in database 0`, which matched
neither of the originally-guessed substrings (`unknown index` / `no such index`),
so `IndexesPresent` returned a hard error instead of "not present" — meaning a
fresh deploy (no indexes) would have failed boot instead of rebuilding.
`IndexesPresent` now also matches `not found`. (The earlier belief that this path
could only be covered "later, under #319" was wrong — #319 was the production
deploy migration to valkey-search, and the testcontainer harness already exists.)

## Consequences

- A normal indexer restart no longer drops the search index (warm-only).
- No proto/sqlc/web changes. No new error codes (these are operator-facing log
  lines + a fatal boot, not RPC errors).
