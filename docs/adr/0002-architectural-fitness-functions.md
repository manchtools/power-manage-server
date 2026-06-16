# 0002 — Architectural fitness functions (what is locked, and why)

- Status: accepted
- Date: 2026-06-12
- Related: 0000 (terminal-admin threat model), 0001 (AES key rotation), the
  2026-06-12 agent + server security/quality audits, the
  SECURITY_HARDENING_WORKPLAN (WS0).

## Context

The 2026-06 security and architecture sweeps fixed a set of recurring code
smells and confirmed a set of good patterns the codebase already follows. A
one-off fix does not stop the next contributor from reintroducing the smell,
and a good pattern that is only a convention erodes silently. We want the
build to fail when a known-bad shape reappears or a load-bearing invariant is
broken — *executable* architecture rules, not prose.

## Decision

Each Go module ships a dedicated `archtest` package of **architectural fitness
functions**: self-discovering, module-wide invariant tests run as part of the
normal `go test` suite.

Ground rules for every guard:

- **Standard library only** (`go/parser`, `go/ast`, `go/token`,
  `go/printer`). No `golang.org/x/tools` dependency — the guards stay
  hermetic, fast, and identical in shape across repos. Syntactic invariants
  do not need full type resolution; where a guard leans on a naming/structure
  heuristic it documents the heuristic.
- **Self-discovering, never a hardcoded list.** Each guard walks the module
  tree (or reflects over the connect/proto registry) and **asserts it
  inspected a non-empty set** (a "matches-zero" guard) so it can never pass
  vacuously — the classic stale-list failure that fails *open*.
- **Every allowlist is itself guarded.** Legitimate exceptions live in a
  documented allowlist keyed by `path :: rendered-expression`; a
  no-stale-entry check fails the build if an allowlisted site no longer
  exists, so the allowlist cannot rot into a silent escape hatch.

### Guards by module

| Guard | server | sdk | agent | Pins / forbids |
|---|:--:|:--:|:--:|---|
| `TestNoDynamicSQL` | ✅ | — | ✅ | DB query/exec args must be string-literal or named-const SQL — no `fmt.Sprintf`/concatenation. (sdk has no DB.) |
| `TestSecretComparesAreConstantTime` | ✅ | ✅ | ✅ | Secret/MAC/token/signature/fingerprint/digest compares use `subtle.ConstantTimeCompare`/`hmac.Equal`, never `==`/`bytes.Equal`. Presence (`== nil`/`== ""`) and metadata fields excluded. |
| `TestProjectionTablesWrittenOnlyByProjectors` | ✅ | — | — | Request handlers never write `*_projection` directly — they append events; projectors and computed-read-model engines write projections (see below). |
| `TestNoUnabstractedTimeNow` | ✅ | — | ✅ | No direct `time.Now()` calls in runtime code (see clock seam below). |
| `TestNoStdlibJSONOfProtoMessage` | ✅ | — | ✅ | Proto messages are (de)serialised with `protojson`, never stdlib `encoding/json` (WS1b#5). |
| `TestNoUnframedHashPreimage` | ✅ | — | — | Hash/MAC preimages must be length-prefixed / domain-separated, never built by `+`-concatenation or `fmt.Sprintf` of multiple fields (the pre-image-ambiguity class behind WS1 / WS1b#3). |
| `TestSignatureIsOverDeterministicProtoAndSingleRepresentation` | ✅ | — | — | No proto field named `*_canonical` (one representation, no divergent twin); the action signer's `Sign()` is called only from the single canonicalization seam `actionparams.BuildAndSignEnvelope` (ADR 0003). |

### RPC classification (lives next to the handlers, not in `archtest`)

Every RPC is consciously classified, by a self-discovering, matches-zero-guarded
test anchored to the live proto/connect registry — kept beside the code it
guards rather than duplicated in `archtest`:

- **`ControlService`** — every RPC is in exactly one of {public allow-list,
  permission, procedure-alternative}, both directions:
  `server/internal/auth/permissions_parity_test.go`.
- **`InternalService`** — every RPC is either device-origin-bound (request
  carries `device_id`, covered by the gateway-binding completeness guard
  `TestInternalHandlers_GatewayBindingIsSelfDiscovering`) or explicitly listed
  non-device-scoped (gated by the peer-class mTLS listener + session ownership):
  `server/internal/api/internal_service_classification_test.go`. A new
  unclassified InternalService RPC fails the build.

### Other self-discovering guards (in their owning packages)

- **`TestEveryActionTypeHandledInEveryParamsSwitch`**
  (`internal/actionparams/registry_test.go`) — every `ActionType` is handled by
  the single proto-reflection params registry (WS1b#1).
- **`TestExecutionCreatedEmittedTyped`** (`internal/api`) — dispatch emits typed
  `payloads.ExecutionCreated`, never an ad-hoc `map[string]any` (WS1b#2).
- **`TestGeneratedCodeIsRegenerated`** — enforced as CI jobs (sqlc drift in
  `sqlc.yml`; proto regen drift in the sdk repo), not a Go test.

A `dupl`-style cross-file duplication CI backstop was **considered and
deferred** in favour of single-source helpers + completeness tests — see ADR
0021.

### The clock seam (`TestNoUnabstractedTimeNow`)

Time-dependent runtime code (token/cert/session expiry, rate-limit windows,
maintenance-window gating, timestamps, even latency measurement) reads the
current time through an injected seam:

```go
type Thing struct {
    now func() time.Time // clock seam; defaults to time.Now, overridden in tests
}
func NewThing(...) *Thing { return &Thing{ now: time.Now, ... } }
// ... use t.now() instead of time.Now()
```

This extends the seam already used by `internal/crl`, `internal/terminal`,
`internal/compliance` and `internal/gateway/registry` to the whole module, so
every time-dependent path is deterministically testable with a fixed clock
(e.g. a cert issued under a past clock is born expired; the offline scheduler
defers when the injected clock is outside its maintenance window).

The guard bans `time.Now()` **calls**; the bare `time.Now` **value** (the
injection default) is allowed. The single structural exception is
`ulid.Timestamp(time.Now())` — ID generation, where the wall clock seeds the
ULID's time component rather than driving a decision; injecting a clock there
buys no testability. This is a category rule, not a per-site blessing.

**The SDK is intentionally exempt** from the clock guard: it has no
time-*decision* logic. Its only `time.Now()` uses are external-command
duration measurement (intrinsically real wall-clock) and ULID seeding, so a
clock seam buys nothing there.

### Projection-write boundary nuance

`*_projection` rows carry **both** event-sourced columns (written by
projectors replaying events) **and** computed/derived columns written by
specialized engines (the compliance evaluator, the dynamic-group evaluator,
the system-role bootstrap reconciler, the action-signature store adapter).
The invariant the guard protects is therefore "*request handlers append
events; they never write a projection directly*" — the engines are not
request handlers and own derived state. They are allowlisted with per-site
justification. If any of those direct writes is later judged a smell to
refactor into an event + projector, deleting its allowlist entry turns the
call site red — the intended forcing function.

## Adding an allowlist entry

An allowlist entry is a reviewed decision, not a quick unblock. Add the
`path :: rendered-expression` key with a one-sentence justification of *why
the flagged shape is safe here* (e.g. "DDL identifier that cannot be a bind
parameter and comes from a trusted in-process registry"). The no-stale guard
will fail the build if the justification outlives the site. A reviewer should
push back on any entry whose justification is "it was already like this".

## Consequences

- A new contributor who writes `fmt.Sprintf` into a query, compares a token
  with `==`, writes a projection from a handler, or calls `time.Now()` in
  runtime code gets a red build with a pointer to this ADR.
- The guards run in the normal `go test` path (no extra tooling) plus the
  existing generated-code drift jobs (`sqlc.yml`; proto regen in CI).
- Cross-module duplication of the small `archtest` AST helpers is accepted:
  the modules are independently released and their test infrastructure is
  intentionally self-contained. (A shared `sdk/go/archtest` library is a
  possible future consolidation.)
