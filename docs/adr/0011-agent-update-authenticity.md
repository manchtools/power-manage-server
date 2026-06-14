# 0011 — Interim agent-update authenticity: CA-signed expected_sha256 binding

- Status: accepted
- Date: 2026-06-14
- Related: manchtools/power-manage-agent#108; manchtools/power-manage-sdk
  (proto: `AgentUpdateArch.expected_sha256`, `AgentUpdateParams.allow_downgrade`,
  `AppInstallParams.checksum_sha256` required); the 2026-06-12 audits (WS7 of
  the SECURITY_HARDENING_WORKPLAN); ADR 0003 (action signing — the trust root
  this reuses); ADR 0005 (gateway is untrusted for origination).

## Context

The agent self-updates via `ACTION_TYPE_AGENT_UPDATE`: the action carries,
per architecture, a binary URL and a checksum-file URL. The agent downloaded
the checksum file, extracted the hash for its binary, then verified the
downloaded binary against THAT hash. The authenticity of the update therefore
reduced to:

1. TLS to the download origin, and
2. a checksum file fetched from **that same origin**.

An attacker who controls (or MITMs) the download origin serves a tampered
binary AND a checksum file that vouches for it — both checks pass. The same
class applied to `DEB`/`RPM`/`APP_IMAGE` download-and-install actions, where
`checksum_sha256` was optional, so an action with no checksum installed a
binary whose only authenticity was TLS. Binary code-signing would close this
properly but is a larger effort (key management, build-pipeline integration).

## Decision

Bind the expected hash to the **CA-signed action** as the interim authenticity
control, reusing the existing action-signing trust root (ADR 0003) — no new
baked key.

- **`AgentUpdateArch.expected_sha256`** (required, 64 lowercase hex) is the
  AUTHORITATIVE integrity gate. It rides inside the CA-signed action, so the
  agent verifies the downloaded binary against a hash bound to the control
  server's signature. The agent does **not** download or trust a same-origin
  checksum file; `checksum_url` remains only as operator-facing metadata. A
  compromised origin cannot forge the CA signature over the hash.
- **HTTPS-only** downloads, fail-closed before any request, at the single
  `downloadFile` chokepoint (deb/rpm/appimage) and for the agent binary.
- **`AppInstallParams.checksum_sha256` is required** — mandatory integrity for
  download-and-install actions; the agent also rejects an empty checksum
  defense-in-depth.
- **Anti-rollback**: the agent refuses a candidate older than the running
  version (`vYYYY.MM.PP`); an unparseable version fails closed. The bypass,
  `AgentUpdateParams.allow_downgrade`, rides inside the CA-signed action — a
  downgrade is an explicit, authenticated operator decision.
- **Server validation** enforces these at the action boundary (every set arch
  carries a lowercase-hex `expected_sha256`; app installs are https + checksum),
  with a self-discovering test pinning that every param field has a rule.

A future binary code-signing key MUST be **operator-pinnable** (self-host
overridable), never a hardcoded project key.

## Consequences

- Compromise of (or MITM on) the binary download origin no longer yields code
  execution: the tampered binary fails the CA-bound hash check. The relay/
  gateway being untrusted (ADR 0005) is consistent — the hash is signed by
  control, relayed opaquely.
- Operators must populate `expected_sha256` per arch and `checksum_sha256` for
  app installs; actions without them are rejected at create/update time.
- A genuine downgrade now requires `allow_downgrade` on the signed action.
- **Out of scope / deferred** (tracked on agent#108): signing the *release*
  `SHA256SUMS` in a separate identity and verifying it in `install.sh` (the
  initial-install integrity, distinct from self-update), plus an install-time
  update-source allowlist. Both need a real release and a key-management
  decision (cosign keyless vs minisign) to validate end-to-end.
