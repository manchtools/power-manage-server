# 0003 — Action signing binds the full executed envelope

- Status: accepted
- Date: 2026-06-12
- Related: sdk#82; the 2026-06-12 audits (agent F-C2 = server SA-C1); WS1 of
  the SECURITY_HARDENING_WORKPLAN; ADR 0002 (fitness functions).

## Context

Actions dispatched to agents are signed by the control server's CA key so an
agent can prove an action originated from control and was not forged by a
compromised gateway or Valkey relay (trust model: actor #4 — untrusted *for
origination*).

The old signature covered only `SHA-256(domain | actionID : actionType :
base64(paramsJSON))`, and the wire carried two separate representations: a
`params_canonical` JSON blob (verified) and the typed `params` oneof
(executed). The agent verified `params_canonical` but **executed the typed
oneof**, and the signature bound neither `desired_state`, `timeout_seconds`,
`schedule`, nor the target device. A compromised relay could therefore:

- flip `desired_state` PRESENT→ABSENT (turn a signed install into an
  unsigned root deletion),
- swap the executed params while leaving `params_canonical` intact,
- change the timeout or schedule,
- lift a signature onto a different action type (e.g. SYNC), or
- replay a captured action onto a different device.

## Decision

Sign the **full executed envelope** as **deterministic binary protobuf**, and
make the agent execute exactly the bytes it verified.

- A new proto message `pm.SignedActionEnvelope` carries everything that
  executes: `action_id`, `action_type`, `desired_state`, `timeout_seconds`,
  `schedule`, `target_device_id`, and the params oneof.
- The CA signs `proto.MarshalOptions{Deterministic:true}.Marshal(envelope)`
  (helper `verify.MarshalEnvelope`). The signature pre-image is
  `SHA-256( len32(domain) || "power-manage-action" || envelopeBytes )`; the
  length-prefixed domain tag keeps this surface disjoint from any other that
  might share the CA key.
- Those **exact bytes are transported** — push path:
  `ActionDispatch{ bytes envelope, bytes signature }`; pull/offline-sync path:
  `Action.signed_envelope` + `Action.signature` (each synced action is signed
  device-bound at delivery). The agent verifies the signature over the
  received bytes and `proto.Unmarshal`s **those same bytes** to execute.
- Clean break: `Action.params_canonical` and the `params_canonical`/typed-
  `params` split are removed. There is one representation — the executed
  message *is* the verified message. The wire `Action`'s typed fields remain
  only as advisory display/scheduling metadata; execution and every
  security-relevant decision read the verified envelope.

### Re-sign at dispatch / sign-at-delivery; device-bound

There is no stable persisted dispatch-grade signature. The push path signs at
dispatch with the execution id + target device. The offline-sync pull path
signs each delivered action device-bound at delivery (the agent has no
execution id yet — the envelope binds the action's own id; the agent mints the
execution offline). Both bind `target_device_id`, so a captured envelope
cannot be replayed onto another device. The server still stores the canonical
params blob (in the `params_canonical` column) as the source the dispatcher
re-marshals the envelope from — that column is now a params store, not a
signature input. No migration; SDK bump with lock-step deploy.

### Why transporting the bytes (not re-marshalling to compare)

Correctness comes from signing-and-transporting the exact bytes and
unmarshalling those same bytes — never re-marshalling a reconstructed message
to compare. Determinism is belt-and-braces. This is safe because the server
(Go) always signs and the agent (Go) always verifies; the web client never
verifies an action signature, so cross-language/version marshalling drift
cannot bite.

### Two signing layers stay separate

This CA action signature is independent of the taskqueue HMAC envelope
(`taskqueue.Wrap`/`VerifyMiddleware`), which wraps the whole Asynq payload to
keep a compromised Valkey from injecting tasks. Both are required; neither
substitutes for the other.

## Consequences

- A compromised gateway/Valkey cannot swap params, flip desired_state, change
  the timeout/schedule, lift the type onto SYNC, or retarget a device under a
  valid signature. `verify`'s charter pins each of these as a rejected swap.
- The agent's offline scheduler verifies the stored signed envelope before
  every execution; an unsigned/tampered synced action is refused, never run.
- `revertAction` (revert-on-unassign) is the one path that runs a locally
  flipped `desired_state=ABSENT`: it executes the params from the *verified*
  stored envelope with only desired_state overridden, so the executed params
  stay authenticated (a relay cannot inject an install via revert).
- Breaking proto/SDK change, shipped sdk→server→agent in lock-step.
