# 0020 — Fail-closed error discipline (cross-cutting)

- Status: accepted
- Date: 2026-06-15
- Related: WS16 of the SECURITY_HARDENING_WORKPLAN
  (manchtools/power-manage-sdk#113/#114 → PR #115;
  manchtools/power-manage-server#433/#434/#435/#331 → PR #436;
  manchtools/power-manage-agent#127/#128/#129 → PR #130);
  ADR 0005 (the gateway is an untrusted relay); ADR 0017 (agent stream-loop
  fail-closed).

This ADR records the cross-cutting error-discipline decisions of WS16. The
implementation spans the sdk, server, and agent repos.

## Context

A sweep of the request-and-execution boundary found a class of "swallowed
error" sites: a discarded `err`, an ignored decode failure, or an unbounded
context that silently degraded behaviour rather than failing closed. None is a
single dramatic vulnerability; together they are an erosion of the fail-closed
posture the rest of the work plan depends on — a corrupt input quietly produced
a weaker policy, a stale event silently wiped a live grant, a wedged subprocess
ran unbounded, or a removed action vanished without reverting its side effects.

## Decision

The boundary fails closed or surfaces the error; it does not silently degrade.

- **Stream sends honour their context (sdk).** `(*Client).send` observes `ctx`
  for both the send-lock acquisition and the underlying `stream.Send`, so a
  stalled peer (a full HTTP/2 flow-control window) can no longer wedge a sender
  — or every sender queued behind it — past its deadline. A buffered-1 ctx-aware
  send slot replaces the blocking mutex; at most one `stream.Send` is ever in
  flight, preserving on-wire ordering.

- **Cancelled subprocesses are SIGKILL-escalated (sdk).** The exec wrappers
  SIGTERM a cancelled child's process group, then escalate to SIGKILL after a
  bounded grace and read the final status under a second bounded grace, so a
  SIGTERM-ignoring child can no longer pin the reaping goroutine.

- **Grant deletes carry a stale-replay guard (server).** `DeleteUserRoleProjection`
  gained `AND projection_version <= $n` (mirroring `DeleteDeviceAssignedUser`);
  an out-of-order `UserRoleRevoked` replay can no longer wipe a newer re-grant.

- **Unmarshal/dedup/decode failures fail closed or are logged (server, agent).**
  `CreateLuksToken` fails closed on corrupt encryption-action params rather than
  degrading to the floor passphrase policy; `AssignDevice` aborts with
  `CodeInternal` on a dedup-lookup DB error rather than re-emitting duplicate
  assignment events on empty sets; the OSQuery result/inventory paths log a
  JSONB decode failure instead of returning an empty success; the agent's sync
  refuses to delete a removed action whose stored JSON cannot be decoded for
  revert (which would drop the action without reverting its SSH/sudo side
  effects).

- **Detached goroutines recover panics (server).** The `UpdateServerSettings`
  fan-out runs under `recover()`, so a downstream panic is logged rather than
  crashing the control process.

- **Install paths are checksum-gated at the executor boundary (agent).** `DEB`
  installs now run the same `requireVerifiedArtifact` guard (https + non-empty
  checksum) as `RPM`/`AppImage`, because `downloadFile` skips checksum
  verification when the checksum is empty. A compromised gateway/Valkey cannot
  drive a package install over plain HTTP or without a checksum.

- **Long-running actions are time-bounded (agent).** `PACKAGE`/`UPDATE` actions
  get a default timeout when none is set and re-bind a context-aware package
  manager, so a wedged `apt`/`dnf` operation aborts instead of running unbounded.

- **Live terminals are torn down on shutdown (agent).** `CloseAllTerminals`
  reverts every live pm-tty session on agent shutdown, so a session open at
  shutdown does not leave its shell activated.

- **Clean stream shutdown is classified, not re-emitted (server).** The agent
  `Stream` receive loop treats a clean shutdown (`io.EOF` / `context.Canceled` /
  connect `CodeUnknown`+`"EOF"`) as graceful and returns `nil`.

- **Sentinels are matched with `errors.Is`; dead authz is removed.** Sentinel
  comparisons use `errors.Is` (wrapped errors are handled); the unreachable
  device-authz path was removed from the control auth interceptor, with a
  self-discovering guard against its reintroduction.

## Consequences

- Corrupt or adversarial input now produces a clear error or a held-state, not a
  silently weaker policy. A few paths that previously "succeeded" on bad input
  now return `CodeInternal` — callers must treat that as a real failure.
- Self-discovering guards (projection-version predicate present, no `==`
  sentinel comparisons, dead-authz absent, shutdown-teardown caller present)
  keep these from regressing.
