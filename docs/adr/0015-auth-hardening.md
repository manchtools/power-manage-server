# 0015 — Auth hardening: JWT alg pinning, per-user RPC rate limits, credential floors, terminal-token transport, login no-enumeration

- Status: accepted
- Date: 2026-06-14
- Related: the 2026-06-12 audits (WS11 of the SECURITY_HARDENING_WORKPLAN);
  manchtools/power-manage-server#82 (auth-hardening umbrella) and #391
  (terminal-close-on-revoke); ADR 0009 / 0014 (secrets at rest — this removes
  the last plaintext-secrets escape); ADR 0005 (gateway is an untrusted relay).

## Context

WS11 swept the request-auth boundary: JWT validation, the rate limiters, client
IP attribution, the terminal-session WebSocket transport, bootstrap-credential
strength, the login enumeration surface, and the gateway session registry. Most
findings were missing tests over already-correct behaviour; a few were real
gaps. This ADR records the decisions that change behaviour or contract.

## Decision

### JWT — HS256 only (findings 2)

`ValidateToken` already pins `token.Method == HS256`; regression tests now lock
that `alg:none`, HS384/HS512 (even signed with the real secret), and RS256
(RS↔HS confusion) are rejected on the signing-method check, not on expiry/type.
A future loosening of the keyfunc fails those tests.

### Credential entropy floors (findings 4, 9)

- **`CONTROL_JWT_SECRET` must decode (hex or base64) to ≥32 random bytes**, not
  merely be ≥32 characters. A bare passphrase no longer boots; operators
  generate a secret with `openssl rand -base64 48` / `openssl rand -hex 32`,
  mirroring `CONTROL_ENCRYPTION_KEY`. The raw string still signs tokens — this
  gates operator input so a weak secret can't be brute-forced into forging JWTs.
- **`CONTROL_ADMIN_PASSWORD` ≥ 12 chars when set** (the docs once shipped
  `admin`). An empty password with an admin email is the no-bootstrap path, so
  an operator can drop the password from the environment after first boot.
- **Encryption is mandatory — the `CONTROL_ENCRYPTION_KEY_REQUIRED=false`
  plaintext opt-out is removed.** A missing key is now a fatal boot error, so no
  deployment can store IdP/TOTP/LUKS/LPS secrets unencrypted "even by accident"
  (operator decision). This closes the last escape left open by ADR 0009/0014.

### Per-user authenticated-RPC rate limiting (finding 6)

After a token validates, every authenticated control RPC is throttled **per
user** (keyed by user ID, not IP — the caller is authenticated). A generous
general ceiling bounds a stolen token / runaway client; a tighter ceiling
applies on top to the **self-discovered** expensive set — `isExpensiveProcedure`
matches `Evaluate*` / `Search*` / `Rebuild*` / `Query*` / `*Query` (query
evaluation, search, projector rebuild, log/osquery fan-out). Self-discovery
(vs a hand-maintained list that fails open) is guarded by a test that walks the
ControlService descriptor and asserts the matcher recognises ≥1 real procedure.
Unauthenticated client-IP attribution (`X-Forwarded-For` / `X-Real-IP`) is
honoured only from `CONTROL_TRUSTED_PROXIES`, so per-IP limits can't be spoofed.

### Terminal-token transport (finding 5)

The TTY WebSocket bearer token must travel in `Sec-WebSocket-Protocol:
bearer.<token>`. The legacy `?token=` query form is **hard-rejected (401) before
any validation** — query strings leak into reverse-proxy access logs, `Referer`
headers, and devtools. `session_id` stays a query parameter (not a secret). The
web client was migrated in the same change.

### Login no-enumeration (finding 11)

A disabled account with the CORRECT password now returns the same generic
*invalid credentials* (`CodeUnauthenticated`) as a wrong password or a
non-existent account, instead of a distinguishable *account is disabled*
(`CodePermissionDenied`) — a credential holder must not learn account state. The
post-2FA disabled check in `VerifyLoginTOTP` keeps its explicit error (the
second factor is already proven).

### Other hardening

- **Audit redaction of SCIM token hashes (finding 1).** A self-discovering AST
  sweep over the `eventtypes/payloads` structs found `scim_token_hash` (bcrypt of
  the SCIM bearer token) leaking through `ListAuditEvents` — the same class as
  the already-redacted `password_hash` / `backup_codes_hash`. Both SCIM events
  are now redacted; the sweep guards every future secret-bearing payload field.
- **Bounded terminate fan-out (finding 8).** `TerminateTerminalSession` now calls
  the gateway under a 10s context deadline (the bare request ctx had none) with a
  client-level `Timeout` backstop.
- **Session-bump terminal close (server#391 gap).** The terminal revocation
  listener now also handles `UserSessionInvalidated` (emitted by the role/group
  session-version bump), closing live sessions iff `StartTerminal` was lost — not
  only on `UserRoleRevoked`.
- **Coverage-only locks:** trusted-proxy/XFF attribution, rate-limiter key-cap
  LRU eviction, a real-proto request through the validation interceptor, and
  `TerminalSessionRegistry` concurrency under `-race`.

## Consequences

- **Breaking (boot):** deployments using a weak/short `CONTROL_JWT_SECRET`, a
  `<12`-char `CONTROL_ADMIN_PASSWORD`, or relying on
  `CONTROL_ENCRYPTION_KEY_REQUIRED=false` will fail to start until they supply a
  CSPRNG-generated JWT secret, a stronger admin password, and an encryption key.
  This is intentional and documented (control/gateway READMEs, deploy compose /
  setup.sh / .env.example).
- **Breaking (terminal):** clients must send the token via the WebSocket
  subprotocol; the migrated web client already does.
- No proto/SDK/agent changes. The rate-limit and disabled-login responses reuse
  the existing `rate_limited` / `invalid_credentials` error codes, so no new
  i18n keys were needed.
