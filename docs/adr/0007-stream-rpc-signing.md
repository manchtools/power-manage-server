# 0007 — Root agent stream-RPCs are CA-signed per surface

- Status: accepted
- Date: 2026-06-13
- Related: manchtools/power-manage-sdk#95; the 2026-06-12 audits (WS4 of the
  SECURITY_HARDENING_WORKPLAN); ADR 0003 (action signing — the foundation this
  reuses); ADR 0005 (gateway is untrusted for origination).

## Context

Actions are CA-signed and verified fail-closed by the agent (ADR 0003). Four
*other* root primitives, however, travelled the same untrusted gateway/Valkey
relay **unsigned**, and the agent ran each as root with no origination check:

- `OnQuery` (`OSQuery`) — runs osquery as root, including arbitrary `raw_sql`.
- `OnLogQuery` (`LogQuery`) — reads the full systemd journal as root.
- `OnRevokeLuksDeviceKey` (`RevokeLuksDeviceKey`) — performs the destructive,
  irreversible slot-7 device-key wipe.
- `CollectInventory` / `RequestInventory` — runs osquery as root.

A compromised gateway/Valkey (trust-model actor #4 — untrusted *for
origination*) could forge any of these: exfiltrate `/etc/shadow` via a forged
raw-SQL query, read the journal, or wipe a LUKS slot — none of which the action
signing of ADR 0003 covered, because these are not `Action`s.

## Decision

Bring all four under the **same fail-closed CA-signature boundary as actions**,
each with its own **disjoint signing domain**, signed only at the control
server, relayed opaquely by the gateway, verified fail-closed by the agent
before any root work.

### Per-surface domains (sdk `verify`)

`canonicalDigest` is refactored to take an explicit domain; the action path
(`power-manage-action`) stays byte-stable. Four new domains are added —
`power-manage-osquery`, `power-manage-logquery`, `power-manage-luks-revoke`,
`power-manage-inventory` — with `SignDomain(domain, payload)` /
`VerifyDomain(domain, payload, signature)`. The length-prefixed domain tag
makes a signature minted for one surface impossible to replay against another,
even though all five share the CA key.

### Canonical = the message with its signature cleared

Each surface's pre-image is the deterministic protobuf wire bytes of the
message with the `signature` field cleared (`verify.OSQueryCanonical`, etc.) —
the same "sign the bytes that execute" philosophy as ADR 0003, and it
auto-binds every field (incl. future ones) without a hand-maintained field
list. Proto fields added: `OSQuery.signature` (7), `LogQuery.signature` (10),
`RevokeLuksDeviceKey.signature` (2), and `RequestInventory.query_id` (1) +
`signature` (2) so a server-originated collection request becomes bindable.

### Sign at control, relay at gateway, verify at agent

- **Control** signs at each dispatch (`DispatchOSQuery`, `QueryDeviceLogs`,
  `RefreshDeviceInventory`, `RevokeLuksDeviceKey`), fail-closed-loud: a nil
  signer or signing error refuses the dispatch rather than shipping an unsigned
  task the agent would drop.
- The Asynq payloads carry the signature (and `query_id` for inventory). A
  shared `payload.ToProto()` is the single construction site for the wire
  message, used by **both** the control signer and the gateway sender, so the
  bytes the agent re-derives match the bytes control signed — no field-mapping
  drift. (Notably `OSQuery.where` and `LogQuery.source` are not on the wire and
  so are absent on both sides.)
- The **gateway only relays** `payload.Signature` onto the wire message; it
  never calls a signer. It drops a nil payload defensively.
- The **agent** verifies fail-closed before any root work (agent repo): a nil
  verifier refuses (production always has one — a missing CA cert is fatal at
  startup), mirroring the action path.

### Raw SQL is signed, not removed

Raw-SQL osquery is a legitimate admin feature. Rather than disable it, it is
signed like any other query: the canonical binds `raw_sql`, so a compromised
gateway cannot originate or tamper a raw query, while an authorised operator's
query (already RBAC-checked at the control server) still runs. A signed raw
query is exactly as trusted as a signed table query — both come from the
authenticated control server.

### Agent-initiated inventory stays unsigned

`CollectInventory` runs on the agent's own schedule (on connect + every 24h).
That path involves no gateway-relayed command and so carries no forgery risk;
only the **server-originated** `RequestInventory` is signed (delivered to a new
`OnRequestInventory` handler). The periodic path is unchanged.

## Consequences

- A compromised gateway/Valkey cannot originate or tamper an osquery (incl. raw
  SQL), a journal read, an inventory collection, or — most importantly — a LUKS
  slot-7 wipe under a valid signature; nor replay a captured signature onto a
  different `action_id`/`query_id`/`unit`/`table`, nor across surfaces.
- This CA signature is independent of the taskqueue HMAC envelope
  (`taskqueue.Wrap`); both are required, neither substitutes for the other.
- Breaking proto/SDK change, shipped sdk→server→agent in lock-step.
