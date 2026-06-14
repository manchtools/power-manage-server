# 0014 — Secrets at rest: AAD scope, CA key-role separation, hashed LUKS tokens, credential accepted-residual

- Status: accepted
- Date: 2026-06-14
- Related: the 2026-06-12 audits (WS10 of the SECURITY_HARDENING_WORKPLAN);
  ADR 0009 (at-rest secret AAD binding — WS5, the foundation this scopes);
  ADR 0003 (action signing — the CA key also signs actions); ADR 0011 / 0013
  (the operator-choice / accepted-residual posture this mirrors).

## Context

WS10 swept the secret-at-rest surface. WS5 (ADR 0009) had already added AES-GCM
AAD context-binding (`enc:v2`) and applied it to the **relay-exposed** secrets
(LUKS / LPS credentials, which travel through the untrusted gateway relay per
ADR 0005). The remaining audit findings span the CA key, LUKS one-time tokens,
the TOTP audit trail, the gateway ops endpoint, and the agent credential store.

## Decision

### Done (cheap, contained)

- **LUKS one-time token hashed at rest** (#3). `device_handler.CreateLuksToken`
  stores `sha256(token)` and returns the plaintext to the caller once;
  `ProxyValidateLuksToken` hashes the presented token before lookup. Migration
  013 clears any lingering plaintext rows (one-time, 15-min TTL). Now consistent
  with registration/terminal tokens.
- **CA key-role separation asserted at boot** (#7). The CA private key signs
  both issued certificates AND dispatched actions (`verify.ActionSigner`, which
  supports only ECDSA/RSA). `ca.NewFromPEM` now rejects a signer-incompatible
  key (e.g. Ed25519, which `parsePrivateKey` would otherwise accept) at boot,
  rather than load and silently break action dispatch.
- **CA key-file permission warning** (#11). `ca.New` warns (does not fail —
  hard-failing would break an existing deployment with a looser mode) when the
  CA private key is group/world-accessible; the operator must `chmod 0600`.
- **TOTP audit redaction** (#8). The audit log redacts `secret_encrypted` and
  `backup_codes_hash` from TOTP setup / backup-code-regeneration events. A
  self-discovering test reflects the payload structs and fails closed if a new
  secret-bearing field or TOTP event is added without coverage.
- **Ops `/health` no longer leaks fleet size** (#12). The unauthenticated
  gateway ops endpoint reports liveness only, not the connected-agent count.
- **Agent credential store fail-closed perms** (#2/#6). The store refuses a
  group/world-writable directory (forgeable salt/ciphertext) and tightens an
  existing directory to `0700` on Save; files are `0600`. Cross-machine and
  salt-substitution binding are pinned by tests.

### Deliberately NOT done (scope calls)

- **idp / TOTP secret AAD wiring (the rest of #9) — deferred.** WS5 AAD-bound
  the relay-exposed secrets, where in-transit relocation/substitution is a real
  attack. idp client secrets and TOTP secrets live **only in the control DB**;
  AAD there is marginal defense-in-depth (it defends against an attacker who can
  already write the DB) and wiring it means converting every encrypt/decrypt
  pair in lockstep — a single missed decrypt site breaks **SSO login or 2FA**.
  The blast radius is not worth the marginal gain. The crypto layer supports
  AAD (`EncryptWithContext`); extending it to these sinks can be revisited if
  the threat model changes.
- **Agent credential KDF rework (#1) — accepted residual.** The proposal was to
  mix a `0600` root-only key file into the KDF instead of (only) the
  world-readable machine ID. But both the key file and the machine ID live on
  the **same disk**, so neither defends the actual residual threat — offline
  theft of the disk or a backup. The honest protections are the `0600`/`0700`
  perms (now fail-closed) and **full-disk encryption**. A same-disk key file
  adds ceremony, not security, so it is not used. (Mirrors ADR 0011 / 0013.)
- **Agent reuse-detection hash salting (#4) — accepted residual.** The LPS/LUKS
  reuse-detection hashes live in the agent's root-only `0600` SQLite DB. Salting
  them resists precomputation only after a root-only DB is already exfiltrated —
  marginal. Documented, not changed. (agent#62's actual concern — cleartext
  passwords reaching the control event store — is resolved: the password is
  stripped before enqueue and never enters agent stdout/`output_json`.)
- **Action-output redaction generality (#10) — accepted and documented.**
  `sanitizeForLog` scrubs the `enc:v1:` marker only; it is not a general secret
  filter. `output_json` is protected by the `0600` DB file perms.

## Consequences

- LUKS tokens, like all other token classes, are unusable if read from the DB.
- A misprovisioned CA key (wrong algorithm, loose perms) is caught at boot.
- The TOTP secret/backup-code material no longer appears in the audit trail.
- The agent credential store cannot be forged by a non-owner; its at-rest
  confidentiality against offline theft is explicitly delegated to full-disk
  encryption.
