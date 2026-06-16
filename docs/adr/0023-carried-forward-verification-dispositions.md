# 0023 — Carried-forward verification dispositions (CF4 / CF5 / CF6)

**Status:** Accepted (2026-06-16)

## Context

The security & RBAC hardening work plan carried three items forward from the
2026-06-10 audit that were *not* findings in the later (2026-06-12) audits and
so were not owned by any work stream. The plan's standing rule for them was
explicit: **verify, do NOT silently drop** — each must end either as a code fix
or as a recorded accept/defer decision. This ADR is that record; previously the
disposition of two of the three lived only in the plan document.

The three items:

- **CF6 — concurrent-renewal version-guard / CAS.** Two concurrent
  `RenewCertificate` calls for one device could both pass the fingerprint check
  and both issue a certificate (double-issue), leaving a valid-but-untracked
  live cert whose fingerprint never lands in the projection.
- **CF5 — projection fire-and-forget watermark.** `Store.fireListeners` is
  synchronous and post-commit, but a listener that never runs (crash between
  commit and projection write, or a swallowed projector panic) leaves the
  projection permanently behind with no automatic re-drive. This is the
  *under-application* failure, orthogonal to the `projection_version` guards
  (which prevent *over-application* by a stale replay).
- **CF4 — golden-corpus / event-versioning.** A deterministic projection-replay
  corpus plus event-schema versioning; a robustness/testing nice-to-have with no
  associated finding.

## Decision

- **CF6 — FIXED.** `RenewCertificate` now serializes per device under
  `Store.WithAdvisoryLock` (the established last-admin / dynamic-group locking
  pattern): the fingerprint read+compare and the `DeviceCertRenewed` append run
  together under the lock, so a second concurrent renewal blocks, re-reads the
  advanced fingerprint, and is rejected as unrecognized instead of minting a
  second certificate. A deterministic concurrency regression test pins it (see
  `internal/api/certificate_handler_test.go`). Closes
  `manchtools/power-manage-server#441` (PR #442). ADR 0016's deferral note is
  updated to point here.

- **CF5 — ACCEPTED (rebuild-on-demand; no automatic watermark).** We do **not**
  add an automatic catch-up watermark. The window is narrow (synchronous,
  post-commit `fireListeners`; a swallowed projector panic is logged), and
  `RebuildAll` is the operator recovery path that re-projects from the immutable
  event log (the events table is append-only and the source of truth — see ADR
  0005). An automatic watermark/lag-tracker is recorded as a possible future
  robustness item but is out of scope for 1.0. Operators who suspect a dropped
  projection write run a rebuild; no state is lost because the events are
  retained.

- **CF4 — DEFERRED (recorded, not lost).** The golden-corpus replay harness and
  event-schema versioning are deferred as a post-1.0 robustness item. There is
  no compatibility pressure today (single in-support agent/proto version, clean
  breaks allowed), so a versioning scheme would be speculative. Tracked here so
  it is not forgotten.

## Consequences

- The plan's "do not silently drop" rule is satisfied for all three carried
  items: one fix and two recorded decisions.
- CF5/CF4 remain **accepted residuals** — they are deliberate, not gaps. If the
  deployment model changes (multiple in-support proto versions; or evidence of
  real dropped-write incidents) revisit CF4/CF5 respectively.
- No proto/SDK/web changes.
