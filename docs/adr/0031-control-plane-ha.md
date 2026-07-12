# 0031 — Multi-instance control plane (HA) without leader election

- Status: accepted
- Date: 2026-07-12
- Related: spec 31 (`06-specs/31-gateway-enrollment-and-control-ha.md`, Part E);
  ADR 0029 (Postgres state is event-sourced — the idempotent-projection
  contract this relies on); spec 29 (task-metadata HMAC — already assumes a
  shared signing key across the fan-out); ADR 0025 (mTLS identity model).

## Context

Operators want to run N control replicas behind a load balancer for
availability and horizontal read capacity. Control is a stateless request
processor over shared Postgres + Valkey: all durable state is the event store
and its projections, and every secret that authenticates or encrypts
(`CONTROL_CA_KEY`, `CONTROL_JWT_SECRET`, `CONTROL_ENCRYPTION_KEY`,
`PM_TASK_SIGNING_KEY`) is already externalized config. The question is whether
running several replicas needs new coordination machinery (a leader, a lease, a
consensus layer) or whether the existing primitives already make replicas
fungible.

Two hazards distinguish "stateless" from "actually replica-safe":

1. **Duplicated periodic work.** Any replica running a timer that emits events
   (retention prune, inventory scheduling, dynamic-group evaluation,
   stale-execution expiry) would, with N replicas, emit N copies per tick.
2. **Replica-local request state.** Any multi-step flow that stashes
   intermediate state in a replica's memory breaks when the load balancer routes
   the second step to a different replica. The OIDC authorization-code flow
   (state + nonce + PKCE verifier created at login-start, read at callback) is
   the one such flow.

## Decision

**Control replicas are fungible; no leader election.** The model is:

1. **Shared crypto material, identical across replicas.** No key is minted
   per-replica. All four secrets stay in config and must be byte-identical on
   every replica. A per-replica CA/JWT/encryption key would fracture trust and
   is explicitly rejected. (Giving each control replica its own mTLS identity
   buys nothing — they share the CA key anyway — so control-instance enrollment
   is out of scope; the generic gateway enroll RPC could serve it later if a
   reason emerges.)

2. **Idempotent projectors, one apply per append.** Projections are written by
   synchronous post-commit Go listeners using `ON CONFLICT` / version-guarded
   upserts (ADR 0029). Whichever replica handles the append runs the projector
   once; the append's optimistic-concurrency version is the cross-replica
   first-writer-wins. No cross-replica double-projection, no missed projection.

3. **Periodic work single-flights on a Postgres advisory lock.** Every replica
   runs every timer, but the tick body runs under
   `store.TryWithAdvisoryLock(key, fn)` — a non-blocking `pg_try_advisory_lock`.
   Exactly one replica acquires the lock per tick and does the work; the others
   skip (`ran=false`) without error. This already covered retention
   (`advisoryKeyPrune`), inventory scheduling (`advisoryKeyInventorySchedule`),
   and dynamic-group evaluation. Spec 31 closes the **fourth**: the
   stale-execution-expiry loop now runs under `advisoryKeyStaleExpiry`, so N
   replicas emit at most one `ExecutionTimedOut` per stale execution per tick.

4. **OIDC flow state lives in Postgres, never replica-local memory.**
   `GetSSOLoginURL` persists `{state, nonce, code_verifier, redirect_uri}` to the
   shared `auth_states` table; `SSOCallback` consumes it from that table. A flow
   begun on replica A therefore completes on replica B, and `Consume` is
   single-use so a replayed callback landing on a third replica finds nothing.
   This was already the design; spec 31 adds a regression test that pins it.

**Why no leader election.** A leader/lease adds a failure mode (split-brain,
lease expiry, failover latency) to buy coordination the advisory locks already
provide at per-task granularity — and finer: each periodic task single-flights
independently, so a slow prune never blocks inventory scheduling. Consensus is
warranted when replicas must agree on *shared mutable in-memory state*; control
has none — the event store is the single source of truth and Postgres is the
coordinator.

## Consequences

- **Deploy is trivial.** Scale control replicas behind an L7 load balancer
  sharing one Postgres + one Valkey; set the four secrets identically. The
  advisory-lock fix is safe to deploy on a single instance too — it just takes a
  lock it never contends.
- **Advisory-lock keys are a shared namespace.** New periodic work MUST pick a
  distinct key constant (they are ad-hoc `int64` hex tags today); a collision
  would make two unrelated tasks contend. Documented at each key's definition.
- **Postgres is the coordination bottleneck.** Advisory locks and the event
  store funnel through one primary. This is the intended tradeoff — correctness
  and operational simplicity over write-scaling — and matches the existing
  single-primary assumption. Read replicas / write-sharding are a separate,
  future concern, not blocked by this decision.
- **No per-replica observability of "who ran the tick."** The winning replica
  logs the work; losers log a debug skip. Sufficient for now; a metric could be
  added if operators need to see lock-winner distribution.
