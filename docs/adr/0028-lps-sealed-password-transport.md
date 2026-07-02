# 0028 — LPS sealed password transport (agent-side seal to a control-owned key)

- Status: accepted
- Date: 2026-07-02
- Related: manchtools/power-manage-agent#62; spec `docs/content/06-specs/18-lps-sealed-transport.md`;
  ADR 0007 (per-surface CA signing domains); ADR 0009 (AES-GCM AAD at rest);
  ADR 0025 (mTLS identity model / five-actor trust).

## Context

LPS (Local Password Solution) rotates local account passwords on managed
devices and retains the new password centrally so an operator can recover it.
The agent generated the password, set it locally (`chpasswd`), and reported it
to control inside the action-result metadata (`lps.rotations`). That report
travelled **agent → gateway → control** as cleartext inside the mTLS tunnels.

The events-table leak was already closed (ADR 0009 / WS5: the gateway strips
`lps.rotations` before enqueueing to Valkey, and control encrypts each password
with AES-256-GCM before appending the `LpsPasswordRotated` event). What remained
was the **gateway** itself: under the five-actor trust model (ADR 0025) the
gateway is the least-trusted server-side actor — it holds no database and no
encryption key precisely so a gateway compromise cannot read secrets at rest.
But LPS passwords crossed it in cleartext in memory, making rotated local
credentials the one high-value secret a compromised gateway could harvest for
every device it relayed. The same cleartext also sat in the agent's own
result-metadata pipeline.

## Decision

Seal each rotated password **on the agent, at generation time**, to a
control-owned X25519 public key. The gateway relays opaque bytes; control
unseals at receipt and re-encrypts with the existing at-rest path. Operator
recovery (`GetDeviceLpsPasswords`) is unchanged.

### Key ownership and distribution

- Control owns one long-lived **X25519** keypair, generated once at boot
  (`EnsureLpsKeypair`, serialized by a PostgreSQL advisory lock, first-writer-
  wins `ON CONFLICT DO NOTHING`). Replicas converge on one key via a single-row
  `lps_keypair` table (migration 010). The private key is stored **only** in the
  application `enc:v2` form (AAD-bound, ADR 0009) — never in cleartext.
- The public key is distributed to agents in the existing `SyncActions`
  response (`LpsPublicKey{public_key, signature}`), **CA-signed** under a new
  WS4 signing domain `power-manage-lps-pubkey` (ADR 0007). The agent verifies
  the signature against its enrollment CA and refuses the key on any mismatch,
  so the relaying gateway cannot substitute a key it controls. The agent
  persists the verified key so rotation keeps working between syncs.

### Sealing construction (SDK `crypto`)

`SealToPublicKey` / `OpenWithPrivateKey`: ephemeral X25519 (fresh per call) +
HKDF-SHA256 (both public keys in the salt, a **mandatory** domain-separation
`info`) + the existing mandatory-AAD AES-256-GCM. The LPS-specific
`SealLpsPassword` / `OpenLpsPassword` are the single source of the `info`
(`power-manage-lps-password:v1`) and the context AAD (`device|action|username`)
so the agent (seal) and control (open) cannot drift — no single-repo test could
catch that drift.

### Fail-closed everywhere

- Agent with no verified key → LPS action fails **before** any `chpasswd` (no
  rotation to a credential that can't be recovered).
- Sync delivers an unverifiable key → refused, previously-stored key kept.
- Agent seals **before** setting the password → a seal failure never rotates.
- Control unseal failure (tampered, wrong key, wrong `device|action|username`
  context) → `InvalidArgument`, **no event appended**, non-retryable so the
  inbox does not loop on a blob that can never open. The batch is staged (unseal
  + re-encrypt + parse the whole set) before any event is appended, so one bad
  entry rolls back the whole batch rather than leaving a partial write.
- The gateway drops any legacy cleartext (`password`) rotation entry loudly and
  never proxies or enqueues it.

### Compatibility (clean-break, paired release)

- Old agent (≤2026.06) + new server: the gateway drops the legacy cleartext
  entries with an ERROR log; the local rotation already happened and becomes
  centrally recoverable again at the first post-upgrade rotation.
- New agent + old server: no key arrives → LPS fails closed, nothing is sent.
- The proto `LpsPasswordRotation` field 2 was re-typed in place
  (`string password` → `bytes sealed_password`) per the project's V1
  clean-break proto policy, so the gateway cannot even represent a cleartext
  rotation.

## Alternatives considered

- **Strip `password` upstream (drop server recovery).** Rejected — recovery
  (`GetDeviceLpsPasswords`) is a shipped feature operators rely on.
- **Accept the wire-cleartext as defense-in-depth** (the interim status quo).
  Rejected — a gateway compromise reads every rotated password; that is the
  gateway's whole threat model, and LPS was its one high-value target.
- **Reuse the CA key to encrypt.** Rejected — the CA key is an ECDSA signing
  key (cannot encrypt), and using one key for both signing and decryption
  violates key separation and turns the CA into a decryption oracle. A dedicated
  X25519 encryption key is required regardless.
- **Unsigned public-key distribution.** Rejected — the untrusted gateway would
  MITM the key and read everything, defeating the feature. The CA signature is
  load-bearing.

## Consequences

- One new single-row table and one boot-time keypair generation; negligible
  runtime cost (sealing is one ephemeral ECDH + one AEAD per rotated user).
- V1 pins a single long-lived keypair. **Keypair rotation** (re-signing, agent
  cache invalidation, unsealing historical blobs) is out of scope and a
  follow-up; the signed-distribution + single-row design leave room for it.
- `StoreLuksKey` has the same gateway-visible-cleartext shape; the primitive and
  key distribution built here make sealing it a small follow-up (tracked
  separately).
