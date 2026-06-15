# 0022 — WS17b boundary hardening: cert-CN binding, search-field sanitization, reconciler-owned role seed

Status: Accepted
Date: 2026-06-15

## Context

WS17b is the server/sdk test-coverage-hardening stream. Most of it adds
rejection-path and self-discovering tests, but four findings flipped or tightened
production behaviour and are recorded here.

## Decisions

### 1. `ValidateLuksToken` enforces the mTLS cert-CN binding (#7)

`AgentHandler.ValidateLuksToken` relayed the caller-supplied `device_id` to the
control proxy without the certificate-identity check that `SyncActions` already
enforced. A compromised agent presenting **device A's** certificate could redeem
a one-time LUKS token issued for **device B** and unlock that device's encrypted
volume.

The cert/`device_id` binding is now a shared `assertDeviceMatchesCert(ctx,
deviceID)` helper that **every** device-scoped agent connect RPC calls before
doing work (currently `ValidateLuksToken` + `SyncActions`, the only two). It is a
no-op when mTLS is not required (dev/test). This is defence-in-depth alongside
the one-time token's TTL + single-use semantics.

### 2. Search warm/index treats agent-controlled fields as untrusted (#17)

`hostname`, `labels`, `os_*`, `kernel`, and `agent_version` are agent-reported
and were written into the Valkey search index verbatim. A malicious or buggy
agent could report a multi-KB value (index bloat / memory pressure) or one
embedding ASCII control characters or `<markup>` (which a UI rendering raw
search-result fields could execute).

A `sanitizeSearchField(s, max)` helper drops control characters, angle brackets,
and invalid UTF-8 and caps length. It is applied on **both** the warm path
(`Index.warmDevices`) and the live path (`worker.entityFields`) so they cannot
drift. `linux_username` and `actor_id` are **operator-set, trusted-by-policy**
and deliberately NOT routed through it.

### 3. System-role permissions are reconciler-owned, not SQL literals (#18)

The Admin/User permission arrays were seeded as SQL literals (`008_seeds.sql`,
patched by `009`/`010`). Each frozen snapshot drifts from the Go source of truth
(`auth.AdminPermissions` / `auth.DefaultUserPermissions`) as permissions are
added/renamed — the Admin literal had already drifted 18 added + 6 renamed
permissions behind. `auth.ReconcileSystemRoles` overwrites them from the Go sets
on every boot, so the literals were runtime-irrelevant but misleading and
un-guardable.

Migration `014` blanks the system-role permission arrays. The reconciler is now
the single source of truth; a self-discovering test asserts no migration leaves a
non-empty frozen literal for the system roles.

### 4b. Compliance evaluator recognizes "no row" via `store.IsNotFound` (#6)

Writing the grace-period/rollup/first_failed_at coverage surfaced a real bug: the
evaluator resolved "no result yet → UNKNOWN" and "first-ever non-compliant → seed
first_failed_at" with `errors.Is(err, store.ErrNotFound)`. The generated queries
return the backend's `pgx.ErrNoRows` — a *different* sentinel — so those branches
never fired; a rule with no result yet, or failing for the first time, errored
instead and aborted the whole device evaluation. Per `store/notfound.go`, callers
outside the store package must use `store.IsNotFound(err)` (it matches both
sentinels); the evaluator now does. A sibling sweep found no other caller with the
pattern.

### 4. `BuildSearchWorkerMux` is fail-closed and testable (#15)

The indexer's mux+signer assembly moved from inline `cmd/indexer/main.go` into
`search.BuildSearchWorkerMux(rdb, signer, logger)`, which returns an error when
the signer is nil (empty `PM_TASK_SIGNING_KEY`) instead of building an unsigned
mux. `RegisterHandlers` mounts the F-02 `VerifyMiddleware` ahead of every
handler, so a forged-key or unsigned `search:*` task dead-letters (SkipRetry)
before any `HSET` — pinned by tests driving forged-key tasks through the real
mux.

## Consequences

- Device-scoped agent RPCs share one cert-binding helper; adding a new one must
  call it (the LUKS-token test pins the pattern).
- Search index fields are bounded and stripped; operator-trusted fields are
  documented as the exception.
- System-role permissions can no longer drift in SQL; the reconciler owns them.
- The sdk request-field validate-tag gate (sdk #121) is now enforced server-side
  via the bumped pin — the validation interceptor rejects out-of-bound request
  fields before the handler runs.
