# 0009 — At-rest secrets are context-bound via AES-GCM AAD

- Status: accepted
- Date: 2026-06-13
- Related: WS5 #8 of the SECURITY_HARDENING_WORKPLAN; the 2026-06-12 audits;
  ADR 0008 (SCIM/SSO identity boundary — sibling WS5 hardening).

## Context

LUKS passphrases and LPS passwords are encrypted at rest with AES-256-GCM
(`internal/crypto`). They were sealed with **nil AAD**, so a ciphertext was not
bound to the row it belongs to: an attacker with database access could relocate
a ciphertext from one device/action row to another and it would still decrypt,
returning the wrong device's secret under a different identity.

## Decision

Bind each at-rest secret to its row context via the GCM additional
authenticated data (AAD), with a versioned prefix so the change is non-breaking.

- `EncryptWithContext(plaintext, aad)` seals with `aad` and tags the output
  `enc:v2:`. `DecryptWithContext(value, aad)` opens `enc:v2:` with the same aad,
  falls back to opening legacy `enc:v1:` with nil aad, and passes non-prefixed
  values through. The original `Encrypt`/`Decrypt` (v1, nil aad) are unchanged
  for callers that don't carry row context (e.g. IdP client secrets).
- The AAD is `SecretAAD(deviceID, actionID, secretType)` =
  `deviceID|actionID|type`. deviceID and actionID are ULIDs (Crockford base32 —
  they cannot contain the `|` separator) and type is a fixed literal
  (`luks`/`lps`), so the concatenation is unambiguous.
- The LUKS/LPS at-rest call-sites (`internal/api/device_handler.go`,
  `internal/api/internal_handler.go`) write `enc:v2:` bound to the row's
  device/action/type and read via `DecryptWithContext`. Reads of pre-migration
  `enc:v1:` rows succeed via the nil-AAD fallback — **no backfill is required**.

## Consequences

- A relocated ciphertext (moved to a different device/action row) fails GCM
  `Open` — the secret is cryptographically pinned to its context, not just to
  the row's primary key. GCM integrity continues to reject byte-tampered
  ciphertext.
- Non-breaking: legacy `enc:v1:` rows keep decrypting; the migration is lazy
  (rows become `enc:v2:` as they're next rotated/written). The shared crypto key
  contract (control + gateway) is unchanged.
- Username is intentionally NOT in the LPS AAD: the primary threat
  (cross-device/action relocation) is closed by `device|action|type`; a
  within-action username swap is a minor residual inside a single trusted
  rotation batch.
- Server-only; no SDK/agent/proto/migration changes.
