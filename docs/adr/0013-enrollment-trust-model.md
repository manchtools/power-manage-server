# 0013 — Agent enrollment trust model: self-service socket, https-only, optional OOB CA pin

- Status: accepted
- Date: 2026-06-14
- Related: manchtools/power-manage-sdk#104; the 2026-06-12 audits (WS9 of the
  SECURITY_HARDENING_WORKPLAN); ADR 0003 (action signing); ADR 0005 (the
  gateway/relay is untrusted for origination); ADR 0011 (the operator-choice
  integrity posture this mirrors).

## Context

A non-root user must be able to enroll their own corporate/BYOD device into
management **without sudo**. That is the entire reason the agent exposes a
local enrollment socket (`/run/pm-agent/enroll.sock`, mode `0666`): a regular
user runs `power-manage-agent enroll …`, the running root daemon performs the
registration, and the registration **token** — validated by the Control Server
— is the authorization.

The 2026-06-12 audit raised the first-enrollment trust gap: the agent has no
trust anchor yet, so it adopts whatever CA the control plane returns. If it can
be pointed at a malicious plane (a cleartext `http://` URL, DNS/MITM, a
drive-by `power-manage://` URI), it would adopt the attacker's CA and then
execute attacker-signed root actions. The audit's heavier proposal was a
CA-signed enrollment-token artifact binding `{control_plane_url,
ca_fingerprint_pin}`.

## Decision

Keep self-service enrollment; harden the cheap, unambiguous surfaces; make the
control-plane-authentication piece an **operator choice**, not mandatory
machinery.

- **The enrollment socket stays world-accessible (`0666`).** Self-service
  no-sudo enrollment is a product requirement. An admin who does not want it
  pre-enrolls devices with a **bulk registration token** (the token is the
  authorization either way). Restricting the socket to root would defeat the
  feature, so we explicitly do **not**.
- **https-only `server_url`** (`sdk.ValidateHTTPSURL`): a cleartext, opaque, or
  hostless control-plane URL is refused before any network call.
- **Bounded bootstrap transport**: `RegisterAgent`/`RenewCertificate` use a
  client with a timeout and a TLS 1.3 floor.
- **Token off argv**: delivery via `-token-file` or `PM_REGISTRATION_TOKEN`;
  `install.sh` writes a `0600` file. `-token` still works but warns (it leaks
  via `/proc/<pid>/cmdline`).
- **Optional out-of-band CA pin** (`EnrollRequest.ca_fingerprint_pin`,
  delivered as `-pin` / `&pin=`): when set, the agent verifies the
  registration-returned CA's SHA-256 fingerprint matches before trusting it.
  Compared case-insensitively, colons stripped (operators paste from openssl).
- **Certificate-rotation CA continuity** (`crypto.VerifyCAContinuity`): on
  renewal the agent adopts a returned CA only if it is byte-identical to, or
  cross-signed by, the enrolled CA — never an unrelated trust-anchor swap over
  the system-roots-fronted renewal channel.

### Why no server-signed enrollment artifact

A CA-signed enrollment artifact adds little for *first-contact* authentication:
the agent cannot verify a CA signature before it has the CA — which is the whole
problem at first contact. All the real value is in the *pin* being delivered
through a trusted channel (the install flow) and compared to the returned CA —
which the optional OOB pin does, without server-side signing machinery, new
key custody, or a web change. This mirrors ADR 0011 (auto-update: optional pin,
lenient default).

## Accepted risk

Without a pin, first enrollment is **trust-on-first-use**. Any local user can
point an *unenrolled* agent at a control plane of their choosing — which is the
direct consequence of, and the cost of, self-service no-sudo enrollment. It is
mitigated by: enroll-at-install (the common flow enrolls immediately as root,
leaving no unenrolled window); **short-lived, single-use, revocable** tokens
(default: one use, 7-day expiry, hashed at rest); the https-only gate (TLS
authenticates the host for an https plane); the optional CA pin for operators
who want first-contact authentication; and admin pre-enrollment via bulk token.
The control plane being public-CA-fronted means TLS already prevents a network
MITM of a correctly-typed https URL.

## Consequences

- Self-service enrollment is preserved; the cheap hardening closes the
  cleartext, argv-token, hung-endpoint, and rotation-trust-swap surfaces.
- Operators who want first-enrollment authentication have an in-product lever
  (the OOB pin) with no new infrastructure.
- **Out of scope / not planned**: a server-signed enrollment artifact and an
  install-time update-source allowlist (the audit's heavier options). Revisit
  only if distribution or the threat model changes such that the OOB pin is
  insufficient.
