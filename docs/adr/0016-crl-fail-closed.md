# 0016 — CRL is fail-closed at boot and on the internal mTLS plane

- Status: accepted
- Date: 2026-06-14
- Related: WS12 of the SECURITY_HARDENING_WORKPLAN; manchtools/power-manage-server#424;
  PR #389 (the base CRL plane this hardens); ADR 0005 (gateway is an untrusted
  relay — revocation is how a compromised gateway/control cert is cut off).

## Context

PR #389 added the Valkey-backed CRL plane: a control-side writer
(`RenewCertificate`/`DeleteDevice` publish fingerprints), a gateway-side
in-memory `crl.Cache` (fail-static refresh), and the gateway AGENT mTLS path
(`MTLSMiddleware`) consulting it. WS12 closes four gaps in that plane.

## Decision

### Fail-closed until loaded (#1, #3, #4)

- `crl.Cache` gains `Loaded()`: false on a brand-new cache and after a refresh
  that only ever errored; true after the first SUCCESSFUL refresh and sticky
  thereafter. This distinguishes "never loaded" (cannot prove anything) from
  "loaded, empty" (a genuinely empty CRL).
- `MTLSMiddleware` now treats a nil checker OR `!Loaded()` as **fail-closed**
  (403 "client certificate revocation unavailable") — we cannot prove the cert
  is unrevoked, so we do not admit. Previously `if revocation != nil { … }`
  silently admitted on both an absent checker and an unloaded cache.
- The only no-CRL path is an explicit, typed `NoopRevocationChecker`
  (`Loaded()==true`) that the caller logs at WARN — never a bare nil.

### Fatal boot (#1)

The gateway refuses to start if the initial CRL load never succeeds (bounded
retry, then `os.Exit(1)`), rather than continuing `ListenAndServeTLS` with an
empty list — a revoked cert must never sail through because Valkey was down at
boot. The decision lives in a testable `loadInitialCRL` helper.

### Internal mTLS plane consults the CRL (#2)

A new `mtls.RequirePeerClassNotRevoked` wraps `RequirePeerClass` with the same
fail-closed revocation gate (peer-class enforced first — additive, not
replaced). It is wired onto:
- the control server's `InternalService` listener (credential-bearing proxy
  RPCs — `ProxyGetLuksKey`, `ProxyStoreLpsPasswords`, …), backed by a
  synchronously-loaded `crl.Cache` that fails the subsystem on initial-load
  error; and
- the gateway's control-class `GatewayService` listener (admin list/terminate
  fan-out).

So a revoked gateway or control certificate is rejected at connect time across
both the agent and internal planes, not usable until natural expiry.

### One RevocationChecker (layering)

The `RevocationChecker` interface and `NoopRevocationChecker` live in `mtls`
(`handler.MTLSMiddleware` consumes `mtls.RevocationChecker`); the prior duplicate
in `handler` was removed. `mtls` cannot import `handler` or `ca` (both import
`mtls` — a cycle), so the fingerprint (`hex(sha256(DER))`, identical to
`ca.FingerprintFromCert`) is computed inline in `mtls`.

## Consequences

- **Operational:** the gateway (and the control internal subsystem) will not
  start if Valkey/CRL is unreachable at boot. This is intentional fail-closed
  behaviour; documented in the gateway/control READMEs.
- A revoked gateway/control cert loses internal-plane access immediately.
- No proto/SDK/web changes. The revocation rejections are mTLS-layer 403s
  (`http.Error`), not Connect `apiError`s, so no new error codes / i18n keys.
- The "concurrent-renewal version-guard / CAS" item carried forward from the
  2026-06-10 audit was a separate verification task (not a WS12 finding) and was
  not addressed here. It has since been **fixed** by serializing
  `RenewCertificate` per device under an advisory lock — see ADR 0023 and
  `manchtools/power-manage-server#441`.

## Update (2026-07-18, audit L11)

The `NoopRevocationChecker` dev opt-out described above (Decision → "Fail-closed
until loaded" and "One RevocationChecker") has been **removed**. It was the one
path by which a no-CRL deployment ran fail-*open*. This strengthens — does not
reverse — the fail-closed decision: the no-CRL path now uses a **bare nil**
checker, which `RequirePeerClassNotRevoked` / `MTLSMiddleware` already treat as
fail-closed (403). A control server with no Valkey/CRL therefore rejects every
gateway call to its internal listener until a real list loads, and there is no
longer any typed opt-out to disable revocation. See `internal/mtls/peer_class.go`
(`RevocationChecker`) and `cmd/control/main.go` (internal-listener wiring).
