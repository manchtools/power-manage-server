# 0021 — Single-source helpers + DRY discipline

- Status: accepted
- Date: 2026-06-15
- Related: WS16b of the SECURITY_HARDENING_WORKPLAN
  (manchtools/power-manage-server#437; the cert/CSR fixture row lands in the
  sdk + agent repos); ADR 0020 (the WS16 fail-closed sweep, whose silent-decode
  fixes motivated centralizing the projector decode).

## Context

DRY in this codebase is enforced *as code is written* — "extract before you
duplicate" is the Definition of Done, and each feature stream collapses the
duplication clusters in the files it touches, in the same PR. WS16b owns only
the residual clusters no single feature stream spans:

1. **Projector payload decode.** ~90 `*FromEvent` decoders in
   `internal/projectors/` each hand-rolled the identical shape: a
   `(stream_type, event_type)` guard returning `ErrIgnoredEvent`, an
   empty-payload guard, a `json.Unmarshal(e.Data, &p)`, and the canonical
   `"projector: invalid <event> payload: %w"` error wrap. No feature stream
   touches all projectors, so the duplication never collapsed inline.
2. **Cert/CSR test fixtures.** ECDSA P-256 CA/cert generation was re-implemented
   in sdk and agent test files (device/user fixtures were already centralized in
   `server/internal/testutil`).

## Decision

- **The strongest DRY mechanism is a single-source helper plus a
  self-discovering completeness test, not a generic similarity tool.** Each
  cluster collapses to one helper that everything consumes, and an AST guard
  makes the *specific* duplication structurally impossible to reintroduce.

- **`decodePayload[T]` (server).** One generic helper centralizes the
  projector decode boilerplate; per-event field validation stays in the caller.
  `TestDecodePayloadHelperUsedByAllProjectors` AST-walks the package and fails
  the build if any `*FromEvent` hand-rolls `json.Unmarshal` without routing
  through the helper, unless it is a recorded exception. The exception
  allowlist is guarded against stale entries and against a vacuous (zero-match)
  walk. The legitimate exceptions are decoders whose payload is empty-valid
  (the event carries no body), whose guard spans two stream types or a runtime
  event-type parameter, or that build a DB-params struct keyed off the
  envelope — shapes the fixed-argument helper cannot express. Decoders that
  route through a shared per-cluster sub-decoder carry no direct
  `json.Unmarshal` and are neither flagged nor allowlisted.

- **Shared cert/CSR test fixtures (sdk-first).** The CA/cert builders move to a
  shared exported helper in the sdk so agent and sdk tests consume one
  implementation.

- **The `dupl` CI backstop is deferred, not adopted.** The work plan specified a
  `dupl` duplication-detection CI job as a *secondary, allowlisted* backstop,
  explicitly blunt on legitimately-similar code. The primary mechanism — the
  single-source helper + self-discovering completeness test above — is stronger
  and noise-free, so we ship that and do not add the `dupl` job (it would
  generate false positives on the many structurally-similar projector/handler
  functions). If a future cluster cannot be guarded by a specific completeness
  test, the `dupl` job is the documented fallback.

## Consequences

- A new projector decoder cannot hand-roll the decode — it must use
  `decodePayload[T]` or justify an allowlist entry under review. The projector
  decode boilerplate shrank by ~300 lines.
- Centralizing the decode also centralizes the error-message form, so a future
  change to the projector decode contract happens in one place.
- The exception allowlist is the honest record of the shapes the helper does
  not cover; the stale-entry guard keeps it shrinking as those shapes are
  refactored.
