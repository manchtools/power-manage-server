# 0008 — SCIM / SSO identity-boundary invariants

- Status: accepted
- Date: 2026-06-13
- Related: WS5 of the SECURITY_HARDENING_WORKPLAN; the 2026-06-12 audits;
  ADR 0007 (stream-RPC signing — sibling boundary-hardening).

## Context

The SCIM provisioning server and the OIDC SSO flow take input from external,
partially-trusted identity providers. The 2026-06-12 audit found several places
where that trust was too broad: a SCIM provider could reach across to another
provider's users, an IdP-asserted email could silently bind to a pre-existing
local password account, a provider disabled for login still accepted SCIM, and
the SCIM auth path leaked provider existence via distinct messages. The OIDC
client also made unbounded outbound calls.

## Decision

Pin the following identity-boundary invariants, fail-closed:

1. **SCIM is provider-scoped (no cross-provider IDOR).** A SCIM provider may
   only add users it OWNS (has an identity link to) to its groups — enforced at
   every member-ADD sink (reconcile, patch-add, patch-replace, create) via
   `verifyProviderOwnership`; unowned members are skipped (logged), mirroring
   SCIM's idempotent member-set semantics. A provider may only read/modify/
   delete its own users (the user-resource verbs already gate on ownership;
   pinned by tests). The REMOVE path is unaffected (it only operates on members
   already in the group).

2. **AutoLinkByEmail requires an explicit trust signal for local password
   accounts.** Binding an IdP-asserted email to a pre-existing LOCAL PASSWORD
   account is an account-takeover vector (any IdP/SCIM operator who can assert
   an email could seize a local admin). SCIM auto-link refuses (409) unless the
   provider has `trust_email_assertions = true` — the operator knowingly
   delegating identity to that IdP. Passwordless / already-SSO accounts are
   linkable (no local credential to hijack). New column via migration 012,
   projected by the Go projector; default false.

3. **SCIM follows the provider login switch.** A provider disabled for login
   (`enabled = false`) rejects SCIM even with a valid bearer — SCIM requires
   both `scim_enabled` AND `enabled`. (If independent SCIM-only operation is
   ever needed it becomes a separate documented flag.)

4. **No SCIM auth existence/timing oracle.** The unknown-provider,
   token-not-configured, and wrong-token branches all return one identical 401
   ("invalid credentials") AND perform a bcrypt compare (against `auth.DummyHash`
   on the no-real-hash branches), so a client cannot distinguish "this slug
   exists" from "wrong token" by message or wall-clock. Distinct Warn lines stay
   server-side.

5. **OIDC outbound calls are timeout-bounded.** Discovery, token exchange, and
   the lazy JWKS keyset fetch run through an `*http.Client` with connect / TLS /
   response-header / overall timeouts, threaded in via `oidc.ClientContext`
   (never `http.DefaultClient`). Signature/issuer/audience/expiry/nonce
   enforcement is unchanged.

6. **CORS allow-all is dev-only and credential-less.** In allow-all mode the
   middleware reflects the Origin but does NOT send
   `Access-Control-Allow-Credentials` (the reflect-any + allow-credentials
   combo is a CSRF/token-theft hole); only explicitly allow-listed origins get
   credentials. The control server refuses to boot with `CORS_ALLOW_ALL` when
   TLS is enabled or the listen address is non-localhost.

## Consequences

- A compromised/over-trusted IdP or SCIM operator cannot reach another
  provider's users, seize a local password account by email assertion, or keep
  provisioning into a disabled provider; SCIM auth no longer leaks provider
  existence.
- A slow/hung IdP cannot hang an SSO request (bounded client); a captured OIDC
  state cannot be replayed at another provider's callback (slug-mismatch).
- `trust_email_assertions` is the one operator opt-in that re-enables
  email→local-password-account linking, for orgs migrating password users to
  SSO.
- Server-only change; no SDK/agent/proto changes. Migration 012 adds a
  defaulted column (no backfill needed).
