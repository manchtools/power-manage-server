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
