# 0025 — mTLS identity model: SPIFFE URI SANs, peer-class enforcement, CA role separation

- Status: accepted
- Date: 2026-06-26
- Related: #324 (foundational ADR backfill). Consolidates the identity foundation
  that ADR 0005 (gateway↔control device-origin binding), 0007 (stream-RPC
  signing), 0013 (enrollment trust model), and 0016 (CRL fail-closed) each build
  on. Cross-referenced from `SECURITY.md`.

## Context

Power Manage is distributed and self-hosted: agents connect to **many** gateways
(internet-facing, keyless, stateless), gateways proxy credential-bearing calls to
**Control** (which holds the database and the CA keys). Every internal hop is
mutual TLS. That demands an identity scheme that (a) distinguishes the three peer
*classes* (an agent must not be able to present itself as a gateway or control),
(b) does not trust the public PKI (a publicly-issued cert must never impersonate
an internal peer), and (c) isolates blast radius if any one signing key leaks.

## Decision

- **Identity is a SPIFFE URI SAN, class-scoped.** Certificates carry
  `spiffe://power-manage/<class>` where `<class>` ∈ {`agent`, `gateway`,
  `control`} as a URI Subject Alternative Name (`internal/ca/ca.go` sets
  `URIs: []*url.URL{peerURI}` on issued certs). The verifier checks the URI's
  class against the class it expects for that connection — peer-class confusion is
  rejected, not just "is this cert from our CA".

- **`tls.RequireAndVerifyClientCert` against a STRICT internal pool.** The gateway
  `GatewayService` and Control `InternalService` listeners verify the client cert
  in-process against the internal CA pool **only** — system/OS roots are never
  added (`internal/mtls/mtls.go`). A certificate from a public CA therefore cannot
  satisfy the handshake even with a matching name.

- **Three separate signing authorities, by role:**
  - **Device-cert CA** — signs agent mTLS client certs (fleet access).
  - **Service-cert CA** — signs gateway/control certs for `InternalService` mTLS.
  - **Action-signing key** — signs `SignedActionEnvelope` and the per-surface
    root-RPC domains (ADR 0003 / 0007). Not a TLS CA, but a distinct key.

  They are independent so a compromise of one does not grant the others (see the
  *CA compromise surface* table in `SECURITY.md`). All three live only on the
  Control host; gateways run keyless.

- **Revocation is fail-closed (ADR 0016).** Revoked/superseded certs are rejected
  via the Valkey-backed CRL; the gateway is fatal at boot if the CRL cannot load,
  so a missing revocation list never silently degrades to "allow".

- **Rotation preserves identity continuity (ADR 0013/0023).** Certs rotate at 80%
  of lifetime; renewal requires proof-of-possession of the current key and is
  serialized per device, so a renewal cannot be used to mint a parallel identity.

## Consequences

- A public-PKI certificate, or an agent cert presented on a gateway/control
  connection, fails the handshake — class and issuer are both enforced.
- Key separation means a leaked device-cert CA is a fleet-access problem but not
  an action-forgery or gateway-impersonation problem (and vice versa).
- The compromise surface is the Control host (where the keys are), not the
  numerous keyless gateways.

## Alternatives considered

- **One CA for all classes** — rejected: a single leak compromises agent access,
  internal service identity, *and* action integrity at once. No blast-radius
  isolation.
- **Trust the system root store for internal mTLS** — rejected: any publicly
  trusted certificate could then impersonate a peer.
- **CN / DNS-name identity** — rejected: SPIFFE URI SANs give an unambiguous,
  class-structured workload identity that the verifier can match exactly, without
  overloading hostname semantics. **This rejection is scoped to *class* identity
  ("what kind of peer").** The *instance* identity ("which specific gateway/agent")
  is carried by the certificate CommonName (the enrolled ULID) and read only after
  the SPIFFE class gate has passed — see ADR 0032, which ratifies that contract.
