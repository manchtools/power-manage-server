# Security Policy

## Reporting a Vulnerability

Please report security vulnerabilities using [GitHub's private vulnerability reporting](https://github.com/manchtools/power-manage-server/security/advisories/new).

Do **not** open a public issue for security vulnerabilities.

## Supported Versions

Only the latest release is supported with security updates.

## Response Time

We address security reports on a best-effort basis. You can expect an initial acknowledgment within a few business days.

---

# Threat model & trust boundaries

Power Manage is **self-hostable and distributed**. The Control server holds the
database and the CA signing key. **Many gateways** may run on separate,
internet-facing hosts with no database and no CA key; they relay over Valkey.
One agent can enroll into any of N independent self-hosted backends. The design
does **not** import SaaS assumptions. The detailed design records live in the
ADRs under `docs/adr/`; this document is the consolidated map.

## Actors

| Actor | Trust | Consequence |
|---|---|---|
| External, unauthenticated | Untrusted | Pre-auth RPCs, enrollment, the OIDC callback and SCIM must reject. |
| Authenticated low-privilege user | Untrusted **for escalation** | RBAC ceiling, `:self`/`:assigned` scope, last-admin protection, IDOR. |
| Control admin / operator | **Trusted** | God-powers are by design; the system is **not** hardened against the operator. |
| Compromised gateway / Valkey relay | Untrusted **for origination** | Action signing and origin binding must neutralize it; any unsigned root path is a bug. |
| MITM / on-path | Untrusted | Transport (TLS 1.3), certificate validation, revocation. |

## Trust assumptions

- **mTLS terminates at the application, not a proxy.** The gateway's
  `GatewayService` and Control's `InternalService` both set
  `tls.RequireAndVerifyClientCert` and verify the peer certificate **in process**
  against the strict internal CA pool only — system roots are never consulted for
  these connections, so a publicly-trusted certificate cannot impersonate a peer.
  Peer identity is a SPIFFE URI SAN (`spiffe://power-manage/{agent,gateway,control}`),
  matched per peer class.
- **The CA signing keys are the crown jewels and live only on Control.** The
  database, the device/service CA keys, and the action-signing key never leave the
  Control host; gateways run keyless and stateless. Protecting the Control host's
  key material (filesystem permissions, host hardening, backups) is the operator's
  responsibility and the single highest-value asset — see *CA compromise surface*
  below.
- **Asynq task integrity is HMAC, not transport.** Every task on the Valkey queues
  is HMAC-signed with `PM_TASK_SIGNING_KEY` (a fatal-at-boot requirement): the
  Control-side producer signs, the consumer (`search:*` indexer worker, per-device
  gateway workers, the `control:inbox` worker) verifies before handling. A
  compromised Valkey relay therefore cannot inject forged or unsigned tasks. This
  is **defense-in-depth distinct from action signing** (which protects the
  *payload* end-to-end at the CA layer): the HMAC binds the *transport queue*, the
  CA envelope binds the *action*.

## Component trust boundaries

| Edge | Mechanism | Fails closed on |
|---|---|---|
| **Agent ↔ Gateway** | mTLS, device-cert CA, SPIFFE URI SAN (`.../agent`) peer-class check, CRL consulted | bad/revoked/wrong-class cert; CRL unloaded at boot |
| **Gateway ↔ Control (`InternalService`)** | mTLS, service-cert CA, SPIFFE URI SAN (`.../gateway`); device-origin bound to the device→gateway registry | cert mismatch; gateway acting for a device it does not own |
| **Control ↔ Postgres** | Password auth over the internal Docker network; not publicly exposed | — (network-isolation assumption; see *Known limitations*) |
| **Control ↔ Valkey** | Password auth over the internal Docker network; **plus** `PM_TASK_SIGNING_KEY` HMAC on every task payload | unsigned/forged task payload |

## Per-surface guarantees

### Action dispatch — a compromised gateway/Valkey cannot forge or tamper (ADR 0003, 0007)

Every dispatched action is a CA-signed `SignedActionEnvelope`: the signature
covers `action_id`, `action_type`, the typed params, `desired_state`,
`timeout_seconds`, `schedule`, and `target_device_id`, over deterministic proto
wire bytes. The agent verifies the signature over the received bytes and
executes **those same bytes** (one representation; no `params_canonical`/typed
split). Therefore a compromised gateway or Valkey relay **cannot**:

- swap params, `desired_state`, `timeout`, or `schedule` under a valid signature;
- re-target a device — cross-device replay is bound out by `target_device_id`;
- lift a signature onto a different action — type is bound by `action_type`.

The same model extends to the previously-unsigned root stream RPCs (osquery,
log-query, LUKS-revoke, inventory): signed at Control with per-surface CA
domains, relayed opaquely by the gateway, and verified fail-closed at the agent
(a nil verifier refuses, never executes unsigned). Raw osquery SQL is permitted
**only** when signed.

### Gateway ↔ Control trust boundary (ADR 0005)

Credential-bearing operations are proxied through Control's `InternalService`;
the gateway never holds DB credentials. Each device-scoped internal call and
each `control:inbox` event is bound to the device→gateway registry and rejected
fail-closed on a mismatch, so a compromised gateway cannot act for a device that
belongs to another gateway, nor write results for a device it does not own. The
`events` table is **append-only at the database layer** (trigger); projections
are the only mutable read model.

### Authorization — a low-privilege user cannot escalate (ADR 0006)

Dynamic RBAC with per-permission granularity. Role-management permission is the
sole gate for granting roles. Scoped permissions (`:self` / device-group scope)
are enforced uniformly at the handler level. Last-admin protection is **atomic**
(advisory-lock serialized across every removal path) so the final administrator
cannot be locked out by a race. Access-token TTL bounds revocation latency;
RefreshToken is checked against the live session. SSO group mapping never grants
admin from IdP claims alone.

### Identity boundary — SCIM / SSO (ADR 0008, 0009)

SCIM operations are confined to their provider (cross-provider IDOR returns 404
on every verb); group-membership writes are ownership-checked. Auto-link by
email is gated behind an explicit `trust_email_assertions` opt-in to prevent
account takeover by an IdP asserting someone else's address; SCIM activation
follows the account's `enabled` state. OIDC verification is bounded and
fail-closed; login does not leak account existence (timing-equalized via a dummy
bcrypt on the miss path). Secrets at rest are AES-GCM with context-binding AAD
(`enc:v2`).

### Agent identity, enrollment & revocation (ADR 0013, 0016)

Agents authenticate by mTLS with certificates signed by the Control CA, pinned
to the agent peer class and verified against the strict internal CA only (system
roots are **not** consulted for the gateway connection, so a publicly-trusted
cert cannot impersonate the gateway). Certificates rotate automatically at 80%
of lifetime; renewal requires proof-of-possession of the current key and is
serialized per device (ADR 0023). Enrollment is https-only with an optional
out-of-band CA-fingerprint pin; revoked/superseded certs are rejected
immediately via the Valkey CRL, and the gateway fails closed if the CRL is
unavailable at boot.

### Agent local privilege & supply chain (ADR 0010, 0011, 0012)

The LUKS passphrase daemon replaces NOPASSWD sudo with a root, token-authorized
socket; file/dir operations are fd-anchored and refuse symlink/TOCTOU swaps.
Package/repo/gpg/flatpak inputs are validated and passed with `--` positional
separation. Self-update integrity is operator-choice: a default tracked
`checksum_url` or an opt-in CA-signed `expected_sha256` pin, https-only, with
anti-rollback.

### Denial-of-service / resource bounds (ADR 0018, 0019)

Pagination is capped; `ReadMaxBytes` bounds every handler; a `statement_timeout`
plus per-handler deadlines bound DB work; CORS rejects credentialed wildcards
and drops Cookies on disallowed origins; offline result spooling is disk-bounded;
the search indexer gates its startup rebuild behind a Valkey lock.

## CA compromise surface

Power Manage runs **three independent CAs**, all rooted on the Control host. Their
blast radii differ, and so does the recovery:

| CA | Signs | If the key leaks | Recovery |
|---|---|---|---|
| **Device-cert CA** | Agent mTLS client certs | An attacker can mint agent certs and connect to gateways as any device | **Replace** the CA, re-enroll agents (or re-issue via the renewal path), and CRL the old chain. Highest urgency — it gates fleet access. |
| **Service-cert CA** | Gateway/Control mTLS (`InternalService`) | An attacker who can also reach the internal network can impersonate a gateway to Control | **Replace** the CA and re-issue gateway/control certs. Contained by network isolation + the device→gateway origin binding. |
| **Action-signing CA** | `SignedActionEnvelope` + the per-surface root-RPC domains (osquery / log-query / LUKS-revoke / inventory) | An attacker can forge actions agents will execute as root | **Replace** the signing key; agents reject envelopes under the old key once Control re-signs. The most dangerous to *execution* integrity. |

Certificates are **re-issued** (cheap, automatic via the 80%-of-lifetime rotation)
for routine expiry; a CA **key compromise** means **replacing** the CA itself —
there is no partial-trust middle ground. Because the keys never leave Control,
the compromise surface is the Control host, not the (keyless) gateways.

## Secrets at rest

Operator-supplied and generated secrets are encrypted with **AES-256-GCM** via
`internal/crypto`, with context-binding AAD (the `enc:v2` envelope) so a
ciphertext cannot be lifted from one record/column to another. The encrypted set:

- **IdP client secrets** (OIDC/SSO configuration),
- **LUKS volume keys** (disk-encryption custody),
- **LPS passwords** (local privileged-service / rotated local credentials),
- **SCIM bearer tokens** (provisioning).

The encryption key is required at boot (no plaintext-by-accident opt-out). Hashed
secrets (e.g. the LUKS-token at-rest hash) live in a root-only database. See
*Accepted residuals* for the deliberate KDF/AAD boundaries.

## Known limitations (out of scope)

The threat model does **not** defend against:

- **A compromised operator workstation or stolen operator session.** The Control
  admin is trusted by design (see *Actors*); an attacker who is the operator has
  the operator's powers. Mitigate with 2FA (TOTP), short access-token TTL, and
  session invalidation — not with in-app hardening against the admin.
- **Supply-chain compromise of the container images / release artifacts.** GitHub
  is the distribution channel; there is no out-of-band signing of release
  `SHA256SUMS` (ADR 0011, accepted risk). Build from source for absolute
  guarantees, and pin image digests.
- **Host / kernel / Docker-daemon compromise on the Control host.** Everything
  (DB, CA keys, plaintext secrets in memory) is reachable from root on that host;
  the internal Postgres/Valkey password boundary assumes the Docker network is
  not already owned.
- **Physical/offline theft of the Control disk** (ADR 0014): the on-disk key file
  is not a defense against same-disk offline theft — full-disk encryption is that
  boundary.

> Operators can run `power-manage-control doctor` to check that a live deployment
> matches the transport/CA/secret expectations this document assumes.

## Accepted residuals

These are deliberate, recorded decisions — not gaps (see the linked ADRs):

- **Same-disk credential KDF / reuse-hash salting** (ADR 0014): the on-disk key
  is not a defense against offline theft of the same disk; full-disk encryption
  is the boundary. The hashed-secret DB is root-only.
- **idp / TOTP at-rest AAD** deferred (ADR 0014): server-only secrets.
- **Self-update `SHA256SUMS` signing / out-of-band release keys** (ADR 0011):
  accepted risk for GitHub-only distribution; build-from-source for absolute
  guarantees.
- **`gpgcheck=false`** is an operator choice, not refused (ADR 0012); https
  transport is still enforced.
- **Enrollment socket mode `0666`** is intentional (no-sudo self-service
  enrollment); the registration token is the authorization (ADR 0013).
- **Projection dropped-write window** accepted with `RebuildAll` recovery; no
  automatic watermark (ADR 0023).
