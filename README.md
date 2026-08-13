# Power Manage

Self-hosted device management for Linux fleets — one binary, embedded SQLite,
mTLS agents, and a transactional audit log.

Power Manage is for teams running tens to thousands of Linux machines —
workstations, servers, kiosks — who need enrollment, desired-state policy,
one-shot dispatch, and audit evidence without operating a database cluster to
get them.

## What it does

- **Enrolls devices over their own outbound connection.** The agent generates
  an Ed25519 key on the device, sends a CSR with a single-use token, pins the
  control CA, and keeps one outbound mTLS stream open. No inbound ports on
  endpoints, no SSH reachability requirement.
- **Applies desired state on a schedule, online or offline.** Actions declare
  `PRESENT`/`ABSENT` for packages (apt, dnf, pacman, zypper — plus flatpak,
  deb, rpm, AppImage), services, files, users and groups, SSH and sshd policy,
  disk encryption, Wi-Fi, and more. Agents store their manifests durably and
  re-apply them on cron or drift intervals even without a server connection,
  honoring per-device maintenance windows.
- **Dispatches one-shot work exactly once.** Explicit dispatches commit
  durably before send, execute once on durable receipt, and bypass maintenance
  windows on purpose.
- **Produces audit evidence by construction.** Every mutation commits in the
  same transaction as its audit operation and effect rows; if audit
  persistence fails, the state change rolls back. Sensitive reads are their
  own audited operations, and secret values never enter logs or audit
  payloads.
<!-- docref: begin src=internal/scim/users_write.go#Handler.provisionSubject:3b57e30f,internal/idp/linker.go#Linker.createUser:7858b2ad,internal/identity/users.go#Handlers.EraseJITUser:6cc8f91a -->
- **Uses enterprise identity from day one.** Human accounts come from SCIM
  lifecycle management or per-provider OIDC just-in-time creation — there is
  no manual user creation and no local passwords. JIT-created subjects have an
  explicit, provenance-gated erasure RPC. First-admin bootstrap is a one-time,
  host-authorized token.
<!-- docref: end -->

Compliance is detection-only by design: policies run detection scripts that
yield a per-device status (compliant, non-compliant, in grace period) —
evidence, not silent remediation.

## Quickstart

You need a Linux host with Docker Compose, two DNS names pointing at it (one
for the browser/API, one for agent mTLS), an email for Let's Encrypt, and an
OIDC provider for operator login. The installer is interactive and asks for
everything it needs; it never prompts for secrets.

```bash
curl -fsSL https://raw.githubusercontent.com/manchtools/power-manage-server/main/deploy/install.sh -o install.sh
chmod +x install.sh && sudo ./install.sh
```

The audit archive must live on a filesystem separate from the database —
control refuses to start otherwise, because evidence that shares a disk with
the records it attests to is not evidence. For a single-disk test box, answer
`loopback` when asked (or set `ARCHIVE_LOOPBACK=1`).

Then bootstrap your identity provider and enroll a device:

```bash
# on the control host: one-time admin token, piped into the CLI
docker compose exec -T control control bootstrap-admin --output token \
  | powermanage bootstrap oidc --file provider.json --token-stdin

powermanage login --provider <slug>
powermanage enrollment-token create --file token.json

# on the device, with the installer from the agent release assets
sudo bash install.sh -s https://agents.example.com -t <token> -p <ca-fingerprint>
```

The operator CLI (`powermanage`) is MIT-licensed and ships from the
[SDK repository](https://github.com/manchtools/power-manage-sdk); the device
agent ships from the
[agent repository](https://github.com/manchtools/power-manage-agent)
with signed releases the installer verifies before anything lands on disk.
Full walkthrough: [deploy/QUICKSTART.md](deploy/QUICKSTART.md).

## Architecture

One control process owns the API, the dedicated agent mTLS listener, identity,
authorization, dispatch, search, and audit, with all state in an embedded
SQLite database (WAL mode, `synchronous=FULL`, FTS5 search). Agents connect
outbound; control never dials a device. There is no external database, queue,
or cache to operate.

## Status and scope

Pre-1.0 release candidates. The RPC contract, storage schema, and agent
protocol may change between versions; pre-1.0 installations are reinstalled
clean rather than upgraded in place.

**CI-tested**, with real package managers and system services in the test
matrix: Debian bookworm, Fedora, Arch, openSUSE (Leap and Tumbleweed), Ubuntu
(apt path), AlmaLinux 9 (library level). Other systemd-based distributions
generally work but are not exercised in CI; non-systemd systems are not
supported.

**Scale:** designed for up to 10,000 normally connected agents on a single
instance. A checked-in scale gate exercises that state volume with hard
latency assertions; it is operator-run rather than continuous CI.

**Deliberately out of scope for version one:** high availability,
multi-region, local passwords/TOTP/WebAuthn, and email notifications
(alerting is a generic HTTPS webhook).

## Where it fits

Configuration management (Ansible, Puppet, Salt) pushes changes to reachable
machines and records that a run happened. Power Manage enrolls devices that
connect outward, keeps desired state applied while they are offline, and
records every change as transactional audit evidence — which matters for
remote fleets and for anyone who has to hand an auditor enrollment records
and continuous policy state rather than playbook logs. Compared to existing
MDM platforms, Linux is the first platform here, not the last checkbox.

## License

The server is [AGPL-3.0](LICENSE). The device agent is GPL-3.0, and the
protobuf contract, SDK, and operator CLI are MIT — you can build your own
client against the published contract.

Contributions: see [CONTRIBUTING.md](CONTRIBUTING.md).
