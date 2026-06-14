# 0017 — Agent stream-loop fail-closed + panic isolation

- Status: accepted
- Date: 2026-06-14
- Related: WS15 of the SECURITY_HARDENING_WORKPLAN
  (manchtools/power-manage-sdk#109 / PR #110; manchtools/power-manage-agent#117 / PR #118);
  ADR 0005 (the gateway is an untrusted relay — the agent must defend against a
  malicious/compromised relay's stream); ADR 0001 (action signing — the envelope
  verification that already nil-guards malformed Actions).

This ADR is recorded in the server ADR series for trust-model continuity; the
implementation lives in the sdk and agent repos (no server code changed).

## Context

The agent runs a long-lived bidirectional stream against the gateway, which
ADR 0005 treats as an untrusted relay. A malformed, oversized, or
panic-inducing `ServerMessage` from that relay must not be able to DoS the
agent (or the whole fleet), bypass the maintenance gate, double-apply a
non-idempotent action across a crash, or downgrade the control channel to
cleartext. WS15 hardens the stream dispatch loop and the scheduler/CLI guards.

## Decision

- **Per-message panic isolation (sdk).** `dispatchServerMessage` wraps each
  message in a scoped `recover()`: a handler panic is logged and converted to a
  non-fatal outcome so the receive loop survives, rather than unwinding the
  goroutine and crash-looping the agent. Genuine stream send/receive errors
  still return as fatal (the loop reconnects). The goroutine fan-out legs
  (inventory, LUKS-revoke, inventory ticker) run through a `safeGo` helper
  (deferred recover) and stay behind their existing bounded semaphores, so a
  flood of frames can neither panic-crash the process nor spawn unbounded
  goroutines.
- **Malformed-oneof nil-guards (sdk).** Each `ServerMessage` oneof variant is
  nil-guarded before the handler is called (e.g. a `ServerMessage_Action` with a
  nil inner `Action`/`ActionEnvelope` is logged and dropped, never
  dereferenced). The `Action.Id` nil-deref noted in the audit was already closed
  by the ADR 0001 envelope refactor (raw bytes routed through fail-closed
  `VerifyEnvelope` + nil-safe getters); a regression test pins it.
- **Inbound size bound (sdk).** `NewAgentServiceClient` sets
  `connect.WithReadMaxBytes(16 MiB)` so an oversized inbound frame is rejected
  with resource-exhausted instead of being allocated. The long-lived client
  keeps no request timeout (the bidi stream is long-lived).
- **Terminal dimension bounds (agent).** `OnTerminalStart`/`OnTerminalResize`
  validate `0 < cols,rows <= 65535` BEFORE the `uint16` narrowing — start fails
  with a STATE_ERROR, resize is a no-op — so an out-of-range value can no longer
  silently truncate to a `0×0`/`1×N` PTY.
- **Fail-closed maintenance window (agent).** A persisted maintenance window
  that cannot be proto-decoded sets a deny-until-next-sync sentinel
  (`windowDecodeFailed`) so dispatch is denied until the next successful sync
  overwrites it — instead of the previous fail-OPEN (`IsAllowed(nil, t)` treated
  a nil window as always-allowed). The "no persisted row" path is unchanged
  (unconstrained for a never-synced device).
- **Clock clamp (agent).** `calculateNextExecute` (and the group variant) clamp
  the next-execute cursor to `min(computed, now+interval)` so a transient
  forward clock excursion cannot suppress drift-prevention beyond one interval.
- **Crash marker (agent).** An attempted/started marker advances the due cursor
  before `executor.Execute`, so a crash between Execute and RecordExecution does
  not blindly re-dispatch within the same interval (best-effort for
  non-idempotent actions; idempotent ones are unaffected).
- **Consolidated https gateway-URL guard (agent).** One shared
  `requireHTTPSGateway(addr)` (via `url.Parse`: scheme is `https`
  case-insensitively, empty `Opaque`, non-empty `Host`) replaces the
  case-sensitive `strings.HasPrefix("http://")` substring guard that let
  `HTTP://`, `Https://`, `https:opaque`, scheme-less, and `ftp://` values reach
  `WithMTLSFromPEM`. Wired at the real gateway-dial sites (runtime + selftest).

## Consequences

- A malicious/compromised relay cannot DoS the fleet with a panic-inducing or
  oversized `ServerMessage`, cannot bypass the maintenance gate via corrupt
  persisted state, and cannot downgrade the control channel to cleartext.
- The maintenance-window change is a behaviour shift on the corrupt-state path:
  a device with an undecodable persisted window denies scheduled dispatch until
  its next successful sync, rather than running unconstrained. This is
  intentional (fail-closed) and documented in the agent README.
- No server, proto-schema, or web changes. Enforcement is at the agent handler
  (since the stream `Receive` runs no protovalidate).
