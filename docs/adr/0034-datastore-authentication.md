# 0034 — Datastore authentication: per-service ACLs + mutual TLS

- Status: accepted
- Date: 2026-07-19
- Related: spec 32 (docs repo, `06-specs/32-datastore-auth-hardening.md`);
  ADR 0031 (control-plane HA — the topology that makes cleartext untenable);
  ADR 0032 (gateway instance identity — the CA identity model this reuses);
  spec 29 task-HMAC (the compensating control for the shared Asynq keyspace);
  `04-security/08-deployment-hardening.md` (docs repo — Traefik/Docker-socket,
  the other half of the Traefik threat).

## Context

Both datastores were protected by a single shared password each and ran
cleartext on the wire: one Valkey `requirepass` shared by control, gateway,
indexer, and the internet-facing Traefik (full keyspace for every holder — CRL
poisoning, route rewrite, queue deletion); Postgres password auth with
`sslmode=disable`. On a single host with no published ports that is contained;
the spec-31 HA topology spreads components across hosts, so shared-credential +
cleartext becomes real exposure. Spec 31's CA already issues per-component
certificates, so there is no reason to phase a weaker tier first.

## Decision

1. **Mutual TLS is the only posture, both datastores.** Valkey: `port 0`,
   `tls-port`, `tls-auth-clients yes`. Postgres: `hostssl … cert
   clientcert=verify-full`, cert `CN` → DB role, passwords dropped. All four
   binaries fail closed at boot without their client cert
   (`datastore.RequirePostgresTLS`, non-nil Valkey TLS config). No plaintext
   fallback exists.
2. **Per-service Valkey ACL users**, each with its own crypto-strong secret
   behind the cert-gated transport: `pm-control` (broad, minus `@dangerous`),
   `pm-gateway` (own namespaces, **CRL read-only** — `%R~pm:crl:*`, so a
   compromised gateway cannot un-revoke certificates), `pm-indexer` (confined
   to `asynq:*` + the search-index namespaces, no `pm:*`/`traefik/*`),
   `pm-traefik` (**read-only `traefik/*`**, the smallest surface for the
   internet-facing component). Destructive/admin commands are denied to all.
3. **Postgres role model unchanged**: control is the owner (migrations + trust
   root), `pm_indexer` stays `SELECT`-only. Secret-bearing columns are AES-GCM
   encrypted at rest, so the indexer's broad `SELECT` yields ciphertext only.
4. **Provisioning is self-contained in `setup.sh`**: it issues the datastore
   server certs and per-component client certs from the deployment CA, mints
   the four ACL secrets (regenerating empty *or* `CHANGE_ME*` placeholder
   values), and renders `valkey.conf`. Container images that drop privileges
   (valkey-bundle uid 999, postgres uid 70) cannot read root-owned `0600`
   keys, so the compose entrypoints copy the key to `/tmp` and `chown` it to
   the runtime user before exec — a deliberate, deployment-tested pattern.
5. **`control doctor` reports posture, never secrets**: ACL user, mTLS on/off,
   client-cert CNs; a plaintext configuration is a Warning. When the TLS
   config is absent or incomplete the probe withholds the ACL credentials
   entirely rather than sending them over a cleartext dial.

## Consequences

- **Breaking, coordinated deploy change**: certs and ACL users must exist
  before services restart; existing deploys re-run `setup.sh` first. A service
  without its client cert does not boot — by design.
- **ACL scopes are maintained allow-lists.** A legitimate new key namespace
  surfaces as `NOPERM`; the fix is widening that one user's grant narrowly
  (as done for control's search-prefix grant), never reverting to `~*`.
- **Accepted residual**: the three task-queue participants share Asynq's
  `asynq:*` bookkeeping keyspace — per-queue key isolation is not achievable
  in Asynq. Cross-queue tampering within that shared keyspace is compensated
  by the spec-29 task-HMAC (forgery-proof payloads), and the deployment E2E
  smoke test asserts the `NOPERM` boundaries that *are* enforceable.
- **Rotation is operator-driven, and a plain `setup.sh` re-run does NOT
  rotate**: set values are deliberately preserved (idempotent upgrades). To
  rotate an ACL secret, clear its `VALKEY_*_PASSWORD` line in `.env` (or set
  it to `CHANGE_ME`), re-run `setup.sh` (mints a fresh secret, re-renders
  `valkey.conf`), and restart Valkey plus the affected service. Certificate
  rotation follows the same pattern via the CA. No auto-rotation.
