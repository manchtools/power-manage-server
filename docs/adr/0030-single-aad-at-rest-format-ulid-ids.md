# 0030 — One AAD-bound at-rest format; ULID identifiers everywhere

- Status: accepted
- Date: 2026-07-04
- Related: spec 20 (docs repo, `06-specs/20-single-aad-encryption-format.md`);
  manchtools/power-manage-server#504; ADR 0009 (AES-GCM AAD at rest —
  **superseded** by this ADR's single-format framing); ADR 0001 (key
  rotation — unchanged); TECH_DEBT_AUDIT.md F-06 + F-15; spec 19
  (retention/erasure — its per-user DEKs wrap under this format).

## Context

At-rest secret encryption shipped two wire formats: `enc:v1` (nil-AAD,
IdP client secrets + TOTP secrets — the WS10 deferral) and `enc:v2`
(AAD-bound, LPS/LUKS/the LPS keypair, per ADR 0009). The public naked
`Encrypt`/`Decrypt` invited new nil-AAD call sites, and a ciphertext
could be relocated across rows/contexts undetected in the nil-AAD
domains. Separately, `luks_keys`, `luks_tokens`, `lps_passwords`,
`security_alerts.event_id`, and `events.id` still used DB-minted
`gen_random_uuid()` identifiers — two ID regimes in one schema, and,
for projection rows, ids a replay could not reproduce.

## Decision

1. **One at-rest format.** AAD-bound AES-256-GCM under the tag
   `enc:v1`. The nil-AAD API is deleted; `EncryptWithContext` refuses
   an empty AAD; `DecryptWithContext` errors loudly on any other
   `enc:*` tag (a beta Path-A deployment reprovisions — retired
   ciphertext is never silently mis-read). AAD dimensions: LPS/LUKS
   keep `device|action|type`; IdP client secrets bind
   `idp_id|idp-client-secret`; TOTP secrets bind `user_id|totp-secret`.
   Guards: `TestAEADStaysInCryptoPackage` (no AEAD primitives outside
   `internal/crypto`, no literal-nil AAD).
2. **ULID identifiers, minted deterministically.** `events.id` is a
   Go-minted ULID; secret-history and security-alert projection rows
   take the raising event's ULID as their id, and their `created_at`
   comes from the event — so a rebuild reproduces the rows
   byte-identically (proven by the spec-21 full-fidelity round-trip).
   `gen_random_uuid()` and uuid-typed columns are gone; the
   `TestULIDOnlyIdentifiers` guard (no `google/uuid` import anywhere
   including generated code; no uuid column/default in migrations)
   keeps a third domain from copying the retired pattern.

## Consequences

- A version tag now marks a genuine incompatible crypto change, not a
  functionality iteration; spec 19's per-user DEK envelope wraps under
  this one format.
- Pre-change deployments must reprovision (beta stance, Path A); the
  decrypt error names the retired tag explicitly.
- KEK custody and rotation are unchanged (ADR 0001); the envelope in
  spec 19 will make hard rotation cheap for DEK'd data.
