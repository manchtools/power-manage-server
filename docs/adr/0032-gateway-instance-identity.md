# 0032 — Gateway instance identity: CN under the SPIFFE class gate

- Status: accepted
- Date: 2026-07-18
- Related: ADR 0025 (mTLS identity model — SPIFFE class SANs; this ADR extends
  it to the *instance* layer it left implicit); ADR 0005 (gateway↔control
  device-origin binding); spec 31 (`06-specs/31-gateway-enrollment-and-control-ha.md`
  — names this reconciliation as a prerequisite); spec 34
  (`06-specs/34-signed-sync-manifest.md` — depends on gateway instance identity
  for the device-origin binding it signs around).

## Context

ADR 0025 established that mTLS **class** identity is a SPIFFE URI SAN
(`spiffe://power-manage/<class>`, class ∈ {agent, gateway, control}), verified by
`mtls.RequirePeerClass`, and explicitly **rejected** "CN / DNS-name identity" —
because overloading the hostname/CN with *class* semantics invites peer-class
confusion (an agent presenting as a gateway).

That rejection was about the **class** layer. It left the **instance** layer
undocumented, and the 2026-07-18 spec audit surfaced the gap: the gateway→device
origin binding reads the *specific* gateway's identity from the certificate
CommonName —

- `server/internal/api/gateway_binding.go:31` — `claimedGatewayID = peerCert.Subject.CommonName`

— which reads, against the letter of ADR 0025, like "CN identity" the earlier ADR
rejected. It is not: this is *instance* identity, not *class* identity, and the
codebase has always worked this way. The CA stamps the enrolled ULID into both
`Subject.CommonName` and `Subject.SerialNumber` for every peer class
(`server/internal/ca/ca.go:224,238`), and `mtls.go:62,82` already reads
`cert.Subject.CommonName` as the agent `deviceID`. Instance-from-CN is an existing,
codebase-wide convention; ADR 0025 simply never wrote it down, so specs 31 and 34
correctly refused to build on an undocumented identity contract.

A gateway certificate therefore carries **three orthogonal identity dimensions**,
each answering a different question:

| Dimension | Field | Answers | Verified by |
|---|---|---|---|
| **Class** | SPIFFE URI SAN `spiffe://power-manage/gateway` | *What kind of peer?* | `mtls.RequirePeerClass` (rejects class confusion, distrusts public PKI) |
| **Instance** | `Subject.CommonName` = `Subject.SerialNumber` = enrolled ULID | *Which gateway?* | consumer handler after the class gate (`gateway_binding.go`) |
| **Server name** | DNS SAN | *What hostname is this serving?* (ServerAuth) | agent's standard TLS `ServerName`/SAN match |

## Decision

**Ratify CN as the gateway (and agent) instance identifier, subordinate to the
SPIFFE class SAN, and require that the instance CN is only ever read after the
class SAN gate has passed.** Concretely:

1. **Class is authoritative and checked first.** Every internal listener verifies
   the SPIFFE class SAN via `RequirePeerClass` / `RequirePeerClassNotRevoked`
   *before* any handler reads the CN. A handler MUST NOT derive instance identity
   from a connection whose class was not already gated. (The `InternalService`
   listener wires `WithPeerCert` after the class + revocation gate —
   `cmd/control/main.go:569` — so `gateway_binding.go` only ever sees
   class-verified peers.)

2. **Instance identity is the CN, and only the CN.** The enrolled ULID in
   `Subject.CommonName` (mirrored in `Subject.SerialNumber`) is the single source
   of "which gateway/agent." A request-body-supplied id that disagrees with the
   peer CN is ignored, never trusted (`gateway_binding.go:30-37`). The DNS SAN is
   **not** an identity input — it is a ServerAuth hostname only, and must never be
   read to answer "which peer."

3. **CN is never overloaded with class semantics.** The CN carries a ULID, which
   is not drawn from the class namespace; class lives exclusively in the SPIFFE
   SAN. This preserves ADR 0025's anti-confusion property: you cannot encode
   "I am a gateway" in the CN, only "I am gateway-instance `01J…`", and the class
   gate has already established the "gateway" part.

4. **The DNS SAN is control-authoritative, not caller-chosen.** Because the DNS
   SAN drives ServerAuth (an agent trusts a gateway's server cert by hostname),
   the enrolling gateway must not choose it freely. Control derives the DNS SAN
   from its configured gateway URL and rejects a mismatched or IP-literal claim
   at issuance (this is spec 31 AC 1, and is the fix for the open
   `gateway_auth_handler.go:101` finding — see spec 31 audit findings).

## Consequences

- Specs 31 and 34 are unblocked: the "superseding trust-model ADR reconciling
  SPIFFE class, CN instance identity, and DNS server name" prerequisite is met by
  this document. Spec 34's device-origin binding may rely on `gateway_binding.go`'s
  CN read as a documented contract.
- No code change is required to *ratify* current behavior; this ADR documents an
  existing invariant. It does, however, make two things enforceable that were
  previously only conventions, and each should gain a guard/test:
  - **Ordering guard:** a handler reading `PeerCertFromContext(...).Subject.CommonName`
    must sit behind a class gate. Worth an archtest or a listener-wiring test so a
    future handler cannot read instance CN off an ungated listener.
  - **DNS-SAN authority (spec 31 AC 1):** the CN/instance ratification here is only
    sound if the *class*-and-*server-name* dimensions are themselves
    control-authoritative. The open finding that any enroll-token holder can put an
    arbitrary DNS SAN in a gateway cert must be closed alongside adopting this ADR,
    or instance identity is trustworthy while server identity is not.
- ADR 0025 is **not** contradicted; it is extended. Its "CN/DNS-name identity
  rejected" clause is scoped, by this ADR, to *class* identity. Add a
  forward-reference from ADR 0025 to ADR 0032.

## Alternatives considered

- **Move instance identity into a second SPIFFE SAN path segment**
  (`spiffe://power-manage/gateway/<ulid>`). Cleaner in theory, but it re-tools
  every issuance and verification site (agents included, via `mtls.go:62,82`) for
  a property the CN already carries correctly, and SPIFFE path-suffix matching is
  easy to get subtly wrong. Rejected as churn without a security gain, given the
  class gate already fronts the CN read.
- **Bind instance identity to the DNS SAN.** Rejected: the DNS SAN is a
  ServerAuth hostname and is (per spec 31 AC 1) operator/deployment-shaped, not a
  stable per-instance key; conflating them is exactly the "overloading hostname
  semantics" ADR 0025 warned against.
