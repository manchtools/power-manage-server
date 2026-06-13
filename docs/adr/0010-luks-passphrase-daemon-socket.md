# 0010 — Agent LUKS passphrase daemon socket (token-authorized, OS-user-independent)

- Status: accepted
- Date: 2026-06-14
- Related: manchtools/power-manage-agent#50, #106;
  manchtools/power-manage-sdk#100 (the fs/TOCTOU half of WS6); the 2026-06-12
  audits (WS6 of the SECURITY_HARDENING_WORKPLAN); ADR 0005 (gateway is
  untrusted for origination).

## Context

Setting a user-defined LUKS slot-7 passphrase
(`device_bound_key_type = USER_PASSPHRASE`) is an interactive flow: a local
user runs `power-manage-agent luks set-passphrase --token <token>`. The agent
runs as root (`User=root`), but this CLI was invoked by an unprivileged user,
so it reached root through a sudoers rule:

```
ALL ALL=(root) NOPASSWD: <binary> luks set-passphrase *
```

The command then read agent credentials from a `--data-dir` flag, connected to
the gateway, validated the token, fetched the managed key, and ran
`cryptsetup`. Two properties of that design are a local privilege escalation
(agent audit #1/#19):

1. **`--data-dir` is attacker-controlled.** The wildcard sudoers rule lets any
   local user pass `--data-dir=/tmp/forged`, so root reads a forged credential
   store — attacker-chosen gateway address, certificate, and device identity —
   and then runs `cryptsetup` against an attacker-chosen device with
   attacker-supplied keys. Root code driven by attacker-controlled trust roots.
2. **Authorization was effectively the sudoers allow-list (any local user),**
   not the server token alone, and the privileged work happened in a
   short-lived unprivileged-launched process rather than the already-root agent.

## Decision

Replace the sudoers rule + `--data-dir` with an **in-process root daemon** the
agent exposes on a Unix socket at `/run/pm-agent/luks.sock` (mode 0666, created
under the systemd unit's `RuntimeDirectory=pm-agent`). The `luks set-passphrase`
CLI becomes an **unprivileged thin client**.

- **The client sends only `{token, passphrase}`** — there is no data-dir or
  store-path field on the wire (enforced structurally + by a test). It performs
  no privileged work.
- **The daemon authorizes against the agent's OWN credentials**, over the
  agent's OWN authenticated gateway connection: it calls `ValidateLuksToken`,
  which the control server consumes atomically. The token is **device-bound,
  single-use, and short-TTL**. Authorization is the **token**, never the OS
  identity of the socket peer — so the socket is world-connectable (0666),
  exactly like the enrollment socket, and AD/SSSD logins are unaffected.
- **Passphrase policy and reuse are enforced in the daemon** (server-
  authoritative), not trusted from the unprivileged client; the reuse history
  is in the now-0600 root-owned `agent.db` the client cannot read.
- **The daemon runs `cryptsetup` with its own root credentials** — no sudo, no
  `--data-dir`, no forgeable store.
- The gateway session is injected per connection (`SetSession`/`ClearSession`);
  when the agent is offline the daemon fails closed (`not_connected`).

The 0666 socket is intentional and safe: connectivity is not authority. A
caller still needs a valid server-issued token to do anything, and the daemon
mints no trust from the connection itself (compare ADR 0005: the relay is
untrusted; here the socket peer is untrusted).

## Consequences

- The `ALL ALL=(root) NOPASSWD: ... luks set-passphrase *` sudoers rule is
  deleted; `install.sh` no longer writes it (and still removes a stale one on
  upgrade). One fewer NOPASSWD root entry on every managed host.
- The `--data-dir` flag is gone from the `luks` subcommand; the forged-store
  escalation class is closed at the source.
- A too-weak/too-short passphrase consumes the one-time token (the client adds a
  basic 16-char floor as UX to avoid the most common waste); a fresh token is
  cheap to mint.
- The flow now requires the agent to be connected to the gateway at the moment
  the passphrase is set (it always did, to fetch the managed key); the failure
  is now an explicit `not_connected` rather than a confusing partial run.
- Companion at-rest hardening: the agent store (`agent.db`) is now created 0600
  and the data dir re-asserted 0700, so the passphrase-reuse history and other
  action secrets are not group/world-readable (agent audit #10).
