# ADR 0001 — AES key rotation for encryption-at-rest

| Status | Date | Scope |
|--------|------|-------|
| Proposed (deferred) | 2026-06-11 | `internal/crypto`, control + gateway env, a re-encrypt job |

## Context

`internal/crypto` encrypts secret values at rest with **AES-256-GCM** under a
**single** 32-byte key supplied as a hex env var and shared by the control and
gateway servers. Ciphertext is stored as `enc:v1:<base64(nonce‖ciphertext)>`;
`Decrypt` is prefix-aware and passes through non-prefixed (pre-migration)
plaintext.

Encrypted data today:
- IdP client secrets (`identity_providers.client_secret_encrypted`)
- LUKS device keys
- LPS passwords
- TOTP secrets (`totp_*.secret_encrypted`)

**The gap (audit):** there is **no key-rotation path**. The key is load-bearing
and permanent — if it is compromised, leaked, or simply aged out, there is no
supported way to move to a new key without orphaning every existing ciphertext
(the old key is gone → undecryptable). AES-256-GCM itself is sound (32-byte key
length-checked, fresh 12-byte `crypto/rand` nonce per op, AEAD — no
padding-oracle surface); the deficiency is purely **operational / crypto-agility**.

Per the 2026-06 audit remediation, rotation is **deferred** as a planned
feature (it is a multi-PR change touching config, the crypto package, and a
data-migration path — not a one-PR fix). This ADR records the design so it can
be picked up cleanly.

## Decision (proposed): versioned keyring + background re-encrypt

Adopt a **keyring** with a **primary** key for new writes, encoding the key
version in the existing `enc:v<n>:` prefix, plus an operator-run re-encrypt
sweep. This is the lightest design that delivers rotation without data loss and
reuses the version prefix already in the wire format.

### 1. Keyring config
- Replace the single-key env with a keyring: an ordered set of
  `version → 32-byte key`, plus a designated **primary** version used for new
  encryptions. e.g. `PM_ENCRYPTION_KEYS="1:<hex>,2:<hex>"`, `PM_ENCRYPTION_PRIMARY=2`.
- Backward-compatible: a lone legacy key maps to **version 1**, and existing
  `enc:v1:` ciphertext is interpreted as "encrypted under key version 1" (today
  the `1` is a *format* version that happens to coincide; the migration pins
  format and key version together at v1 and moves forward).
- The gateway shares the same keyring (it performs credential-proxy ops).

### 2. Encrypt / Decrypt
- `Encrypt` uses the **primary** key and stamps its version: `enc:v<primary>:…`.
- `Decrypt` parses the version from the prefix and selects the matching key from
  the keyring; **fail closed** (error, never silent plaintext) if the version is
  unknown — a value encrypted under a retired key must surface loudly, not be
  treated as plaintext. (The existing pre-migration plaintext passthrough is
  kept ONLY for the no-prefix case.)

### 3. Rotation procedure
1. Generate a new key, add it to the keyring, set it **primary**. New writes use
   it immediately; all old values still decrypt via their (still-present) prior
   key versions. **No downtime, no data loss.**
2. Run the **re-encrypt sweep** (below) until every encrypted value is at the
   primary version.
3. Once the sweep reports zero values at the old version, **retire** the old key
   from the keyring.

### 4. Re-encrypt sweep
- A resumable, rate-limited job (admin-triggered RPC and/or a one-shot CLI) that
  walks every encrypted column, `Decrypt`s with the matching key, re-`Encrypt`s
  with the primary, and writes back via the normal event/projection path
  (no direct projection mutation).
- **Self-discovering target list:** the set of encrypted columns is registered
  in one place (a registry the sweep iterates), guarded against matching zero,
  so a newly-added encrypted column cannot be silently missed — mirrors the
  audit-redaction and permission-key discovery patterns already in the codebase.
- Idempotent: re-running re-encrypts only values not yet at the primary version.

## Consequences
- **Pro:** a compromised/aged key can be rotated out without downtime or data
  loss; crypto-agility for future algorithm changes via the same version prefix.
- **Con:** richer env config (keyring + primary vs one key); a re-encrypt job to
  build, test, and operate; `Decrypt` becomes fail-closed on unknown versions
  (a deliberate behaviour change from today's permissive passthrough, gated to
  the no-prefix case only).
- **Migration compat:** existing `enc:v1:` values are key-version 1; the first
  rotation introduces key-version 2.

## Alternatives considered
- **Full envelope (KEK/DEK):** a per-value random DEK wrapped by a KEK. Rotating
  the **KEK** only re-wraps DEKs (no bulk data re-encrypt). Stronger and the
  industry default at scale, but heavier — per-value wrapped-DEK storage, more
  moving parts. **Rejected for v1:** the encrypted-secret volume here is small,
  so the keyring + sweep is sufficient and simpler; envelope can layer on later
  behind the same version prefix if volume grows.
- **External KMS (Vault / cloud KMS):** out of scope for the self-hosted default;
  a natural pluggable backend later, tied to the storage-abstraction roadmap.
- **Do nothing:** rejected — leaves no recovery from key compromise.

## Out of scope
External KMS integration; automatic scheduled rotation (operator-triggered for
now); re-keying the Asynq HMAC signing key (separate secret, separate ADR if
needed).
