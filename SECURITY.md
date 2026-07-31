# Security policy

## Reporting a vulnerability

Report vulnerabilities privately to the repository maintainers. Do not open a
public issue containing exploit details, credentials, or affected deployment
data.

## Architecture authority

The sole system security design is
`../DESIGN_2026_07_31/00_TARGET_DESIGN.md`. This file describes the
repository's security contract without creating a competing architecture.

## Trust boundaries

- Traefik is the only internet-facing server component.
- The browser authenticates to control with an OIDC-derived session.
- Agents authenticate directly to control with device mTLS certificates.
- PostgreSQL is trusted for availability and persistence during consolidation,
  but a database copy must not reveal plaintext protected secrets.
- The control host and its CA/key material are trusted. A hostile host
  administrator is outside the application threat boundary.

## Required guarantees

### Identity and authorization

Human login is OIDC only, with SCIM for provisioning. MFA belongs to the
identity provider. The bootstrap-admin token is single-use, short-lived, and
cannot act as an ordinary `:self` user.

Every trust-boundary input is validated before authentication and
authorization. Object-scoped non-owner access returns NotFound. Privilege-
widening permissions remain global-only.

### Device transport

The device generates its own Ed25519 key and CSR. Its private key never leaves
the device. Control terminates mTLS, derives device identity from the
certificate, checks revocation during handshake, and closes a live stream when
the certificate is revoked.

Ordinary application frames are not separately signed. There is no untrusted
relay or offline verifier between agent and control.

### Secrets

Classified protobuf fields carry versioned X25519-sealed values. AAD binds
protocol version, direction, message, field, device, and the relevant action,
delivery, or terminal session.

At rest, secret values use AES-256-GCM with resource-context AAD and distinct
domain tags. Transport sealing is not reused as storage encryption.

Logging is metadata-only. Secrets must not enter debug formatting, logs,
errors, traces, audit payloads, or support bundles.

### State and audit

Application state is ordinary CRUD. The audit log is append-only evidence, not
authoritative state. A mutation and its initial operation/effect rows commit in
one transaction. Shared boundaries and exact-set tests enforce coverage for
RPCs, sensitive reads, rejected authentication, SCIM, enrollment, jobs, and
background writers.

Audit streams are hash-chained and periodically anchored off-host. Retention
archives and verifies a prefix before deletion.

### Dispatch

Control commits a complete delivery before send. The agent durably records
receipt before acknowledgement. Stable delivery IDs, connection epochs,
idempotent result ingestion, and an explicit INDETERMINATE outcome prevent
silent replay of non-idempotent effects.

## Deployment requirements

- Do not expose control or PostgreSQL directly to the internet.
- Do not mount the Docker socket into Traefik.
- Restrict the PROXY-protocol listener to the isolated Traefik network.
- Protect CA, JWT, sealing, database, and at-rest encryption keys with strict
  filesystem or deployment-secret permissions.
- Replicate database and artifacts off-host and monitor backup age and lag.

Gateway, Valkey, Asynq, external indexing, CRL distribution, local
password/TOTP, and application-frame signing are not compensating controls and
must not be reintroduced.
