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

Make agent-update integrity a deliberate **operator choice** between
hands-off and pinned, with a floor that an update can never run with *no*
integrity check. The action is already CA-signed (ADR 0003), so its fields
(URLs, hash) cannot be tampered in transit — the only residual concern is a
**manipulated hash at the download origin**.

- **`AgentUpdateArch.checksum_url`** (default) — the agent fetches this
  SHA256SUMS file and verifies the binary against it. This lets an action
  point `binary_url` + `checksum_url` at `releases/latest/...` and have the
  fleet **track new releases hands-off**. Authenticity is origin-trust; an
  operator who wants to remove the single-origin assumption can host the
  checksum file on a **separate host** from the binary.
- **`AgentUpdateArch.expected_sha256`** (optional, 64 lowercase hex) — when
  set, the AUTHORITATIVE gate that **overrides** `checksum_url`. It rides
  inside the CA-signed action, so the agent verifies against a hash bound to
  the control server's signature, not a file from the download origin. Use it
  to pin an exact binary (staged rollouts) or for stronger authenticity. The
  trade-off is that a new version requires updating + re-signing the action,
  so it is opt-in rather than the default.
- **At least one** of `checksum_url` / `expected_sha256` must be set —
  enforced by the server validator AND the agent — so an update is never
  installed with no integrity verification.
- **HTTPS-only** downloads, fail-closed before any request, for the agent
  binary, the checksum file, and the deb/rpm/appimage `downloadFile`
  chokepoint. `AppInstallParams.checksum_sha256` stays **required** (a
  separate path; its mandatory integrity is unchanged).
- **Anti-rollback**: the agent refuses a candidate older than the running
  version (`vYYYY.MM.PP`); an unparseable version fails closed. The bypass,
  `AgentUpdateParams.allow_downgrade`, rides inside the CA-signed action.

A future binary code-signing key MUST be **operator-pinnable** (self-host
overridable), never a hardcoded project key.

## Accepted risk

In the default (`checksum_url`) mode, a **compromised download origin** that
serves a malicious binary *and* a matching checksum file is not detected — the
checksum is self-attesting. This is an accepted risk for prebuilt binaries:

- The control plane provides ease-of-use; the action signature already
  prevents tampering of the action itself. The publisher owns the build
  pipeline and `install.sh`, so signing would not defend against the publisher
  anyway, and out-of-band signing keys are explicitly not planned.
- Operators who need a stronger guarantee have two in-product levers
  (`expected_sha256` pin; a separate-host `checksum_url`), and — since the
  project is open source — the ultimate answer is to **build and distribute
  the binaries themselves** and pin hashes as they require.

This is the same posture as the **initial install** (`install.sh`): TLS + a
self-attesting checksum, no release-`SHA256SUMS` signature. The operator-facing
statement of this lives in the agent README (Auto-Update / install sections).

## Consequences

- The hands-off "track latest" update workflow is preserved (default
  `checksum_url`), while `expected_sha256` remains available as an opt-in pin.
- The CA-signed pin (`expected_sha256`) neutralises an origin/MITM hash
  manipulation for operators who choose it — consistent with the relay being
  untrusted (ADR 0005); the hash is signed by control, relayed opaquely.
- **Out of scope / deferred** (tracked on agent#108): signing the *release*
  `SHA256SUMS` in a separate identity + verifying it in `install.sh`, and an
  install-time update-source allowlist. Per the accepted-risk above these are
  not planned while distribution stays on the publisher's GitHub pipeline with
  no out-of-band keys; revisit only if distribution moves to mirrors the
  publisher does not control, or an out-of-band signing key is adopted.
