# 0005 — Gateway↔control device-origin binding

- Status: accepted; point 3 (single-gateway `nil`-lookup bypass) superseded
  2026-07-18 by spec 31 D6 — `CheckDeviceGatewayBinding` now fails CLOSED on a
  nil resolver. The bypass had become vestigial: Valkey (and with it the
  routing registry) is mandatory for any gateway to function, so no deployment
  without a resolver has a legitimate device-origin caller, and a nil lookup
  can only mean a wiring bug. See ADR 0032 for the instance-identity model
  that replaced the request-body `gateway_id` authority.
- Date: 2026-06-13
- Related: server#403; the 2026-06-12 audit (SA-C2); WS2 of the
  SECURITY_HARDENING_WORKPLAN; sdk#94 (the `gateway_id` wire field);
  ADR 0003 (action signing), ADR 0004 (proto-native representation).

## Context

Two server-side trust boundaries carry **device-origin** traffic from a gateway
to control:

- **InternalService** (gateway → control, mTLS): credential-bearing proxy calls
  — read/store a device's LUKS key, store LPS passwords, sync signed actions,
  verify a device.
- **control:inbox** (gateway → control, Valkey/Asynq): device-attributed events
  — execution results, output chunks, inventory, security alerts, LUKS-revocation
  results, terminal audit chunks.

Before this change both boundaries trusted a *self-asserted* `device_id` with no
proof the calling gateway is the one that device is actually live on:

- The gateway peer-class mTLS cert is **shared** across gateway replicas and
  carries **no per-gateway identity**, so InternalService could not tell which
  gateway was calling — any gateway could read or overwrite **any** device's
  LUKS/LPS secrets (critical, SA-C2 #1).
- control:inbox authenticated only with the **shared `PM_TASK_SIGNING_KEY`
  HMAC** — necessary (it stops tampering in Valkey) but **not sufficient**: any
  holder of the shared key could forge device-attributed events for an arbitrary
  `device_id` (high, SA-C2 #2). The HMAC also can't tell two devices apart, so
  several inbox handlers trusted attacker-chosen `(device_id, execution_id /
  session_id / action_id)` tuples.

## Decision

Bind every device-origin operation to the **authenticated device→gateway routing
binding** — the registry entry the agent's own mTLS-authenticated heartbeat
writes (`AttachDevice`), which *is* the per-gateway identity the shared cert
lacks.

1. **Wire field.** Each device-origin request/event self-asserts a `gateway_id`
   (sdk#94 added it to the 6 `device_id`-carrying InternalService requests;
   `taskqueue` payloads carry it on the inbox side). The gateway producer stamps
   its own id (`ControlProxy`, `AgentHandler`, `TerminalBridgeHandler`).
2. **One binding policy.** `registry.CheckDeviceGatewayBinding(ctx, lookup,
   deviceID, claimedGatewayID)` is the single source, reused by both boundaries.
   Fail-closed: empty `gateway_id` → reject; `ErrNoGateway` (device live on no
   gateway) → reject (never allow-on-unknown); `lookup ≠ claimed` → reject. The
   InternalService handlers map the sentinels to connect codes (after `Validate`,
   validate-then-auth); the inbox worker maps them to `asynq.SkipRetry` drops
   that append no event.
3. **No resolver = fail closed** *(rewritten 2026-07-18; the original point
   documented an allow-on-nil "single-gateway bypass", superseded by spec 31
   D6 — see Status)*. When no resolver is wired (a `nil` lookup), the binding
   check **refuses** the device-origin operation. Control wires the resolver
   whenever the Valkey-backed routing registry is available — which is every
   deployment with a functioning gateway, since Valkey is mandatory for
   gateways — so a nil lookup only occurs on a wiring bug and must never
   silently disable the binding.
4. **Cross-device ownership** (defense the binding does not cover — confining
   *which* resource a device may write, not *which* gateway speaks for it):
   output chunks must belong to the reporting device's execution; a LUKS
   revocation result with no outstanding request is dropped (never mints an
   orphan stream); a terminal audit chunk requires an existing session whose
   `(device, user)` it matches, and `AppendTerminalSessionChunk` is UPDATE-only
   so it can never INSERT an attacker-owned placeholder.
5. **DB-level append-only events** (ADR-adjacent, migration 011): a `BEFORE
   UPDATE/DELETE/TRUNCATE` trigger on `public.events` enforces the audit trail's
   append-only invariant in the database, not only in app code — so even a
   compromised query path or operator with DB access cannot rewrite history.
   `RebuildAll` only TRUNCATEs `*_projection`, so projection rebuilds are
   unaffected.

## Consequences

- A compromised single gateway can no longer pull another device's secrets or
  forge device-attributed events; the audit trail is DB-enforced append-only.
- Binding rejections are returned to the **gateway** (a server component), never
  the web client (the browser talks to ControlService, not InternalService), so
  they reuse existing internal error codes (`validation_failed`,
  `device_not_connected`, `permission_denied`) rather than dedicated
  web-localized ones — no new error-code/i18n surface.
- **Rolling-upgrade note (pre-1.0):** `gateway_id` is optional on the wire
  (`omitempty`); a control with the resolver wired will reject device-origin
  calls from an *un-upgraded* gateway that sends no `gateway_id` until that
  gateway is upgraded. Acceptable while the re-tag-in-place freedom holds, and
  control + gateway ship from one server module.
- `TestInternalHandlers_GatewayBindingIsSelfDiscovering` (completeness-checked
  against the InternalService descriptor) and `TestInbox_RejectsCrossGatewayDeviceOrigin`
  keep both boundaries from regressing as new RPCs/handlers are added.
