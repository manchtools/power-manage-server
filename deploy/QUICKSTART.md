# Power Manage Server — Quickstart

> Before exposing a deployment, read **[../SECURITY.md](../SECURITY.md)** — trust boundaries, what to protect (the Control host's CA keys), and the disclosure process. After install, `control doctor` checks the live stack against those expectations.

One-line install on a fresh Linux host with Docker + the compose plugin already installed:

```bash
curl -fsSL https://raw.githubusercontent.com/manchtools/power-manage-server/main/deploy/install.sh | sudo bash
```

The installer:
1. Verifies `docker` + `docker compose` are present (does **not** install them — you own that step).
2. Downloads the `deploy/` tree from the latest pre-release tag.
3. Copies `.env.example` to `.env` if missing.
4. Runs `setup.sh` in **guided mode** — interactive prompts for domains, ACME email, and admin credentials; auto-generates strong defaults for every secret (Postgres / indexer / Valkey passwords, JWT secret, encryption key).
5. Pulls the Power Manage container images.
6. Brings the stack up via `docker compose up -d`.
7. Prints the URLs and next steps.

## Pinning a specific version

The installer defaults to `latest-rc` (the curated pre-release tag). For a stable release or a specific RC:

```bash
curl -fsSL .../install.sh | sudo RELEASE_TAG=v2026.05 bash
```

> **Note:** the env var goes between `sudo` and `bash`, **not** before `curl`. By default `sudo` resets the environment (`env_reset`), so `RELEASE_TAG=… curl … | sudo bash` would only set the variable for the local `curl` process and the installer running under `sudo` would never see it. Putting it after `sudo` passes it through.

## Non-interactive install

CI / Ansible / preconfigured `.env` setups can skip the guided prompts:

```bash
curl -fsSL .../install.sh | sudo NO_PROMPT=1 bash
```

The installer expects `.env` (or `.env.example` to copy from) at `INSTALL_DIR` and runs `setup.sh --no-prompt` — strict env validation only, no prompts.

## Custom install directory

```bash
curl -fsSL .../install.sh | sudo INSTALL_DIR=/srv/pm bash
```

## Re-running the installer

`install.sh` is idempotent. Re-running on an existing install:
- Preserves `.env` (your secrets stay intact).
- Pulls the chosen `RELEASE_TAG` images.
- Restarts the stack.

Use this for upgrades:

```bash
sudo RELEASE_TAG=v2026.06 bash /opt/power-manage/install.sh   # if previously installed
# or fetch a fresh installer
curl -fsSL .../install.sh | sudo RELEASE_TAG=v2026.06 bash
```

## Manual install (if you'd rather not run a curl-pipe-bash)

```bash
git clone https://github.com/manchtools/power-manage-server.git
cd power-manage-server/deploy
cp .env.example .env
./setup.sh                      # guided env + cert generation
docker compose up -d
```

## What the installer does NOT do

- **Install Docker.** Use [the official convenience script](https://docs.docker.com/engine/install/) or your distro's package manager first.
- **Configure DNS.** You need A/AAAA records pointing your `CONTROL_DOMAIN`, `GATEWAY_DOMAIN`, and (if terminals are enabled) `GATEWAY_TTY_DOMAIN` at this host.
- **Open firewall ports.** Traefik binds `:80` (LE http-01 challenge + redirect-to-https) and `:443` (everything else) on the host. Open those before the first start so Let's Encrypt can issue certificates.
- **Migrate from a pre-rc11 deploy.** This installer is for fresh installs and same-release upgrades. Migrating across breaking releases follows the per-release migration runbook.

## After install

1. Wait ~30 s for Let's Encrypt to issue certs on first run.
2. Log in to `https://<CONTROL_DOMAIN>` with the bootstrap admin credentials the installer printed.
3. Create real user accounts (UI, SSO, or SCIM) — the bootstrap admin is intentionally not for daily use; see [`.env.example`](./.env.example) for details.
4. Generate a registration token and enroll your first agent.

## Health & posture check: `doctor`

<!-- docref: begin src=cmd/control/main.go#@doctor-subcommand:215d5a9d,.github/workflows/release.yml#@control-binary-name:6d502abb -->
The Control binary ships a read-only `doctor` subcommand that checks the live
stack and deployment configuration against the expectations in
[../SECURITY.md](../SECURITY.md). It never mutates state, so it is safe to run
against production. The in-container binary is `control` (run it inside the
running Control container so it sees the same env and `.env`):

```bash
docker compose exec control control doctor          # human-readable
docker compose exec control control doctor --json   # machine-readable
```
<!-- docref: end -->

<!-- docref: begin src=cmd/control/doctor.go#runDoctor:7091dc81 -->
Flags:

- `--json` — emit a JSON report (`{summary, findings, exec_errors, exit_code}`) for CI/monitoring.
- `--env-file <path>` — also inspect this `.env` (default `.env`, silently skipped if absent). Values in the file take precedence over the process environment — it is the operator's stored config, the source of truth for what was configured.
<!-- docref: end -->

<!-- docref: begin src=internal/doctor/registry.go#DefaultChecks:293ef4cc -->
It reports placeholder/weak secrets, mandatory at-rest encryption key, a
credentialed CORS wildcard, an internal mTLS listener bound to all interfaces, a
floating `IMAGE_TAG`, certificate file permissions and approaching expiry,
Postgres/Valkey reachability, Asynq dead-letter depth, search-index presence
and indexer liveness (reconcile heartbeat), remote-terminal (TTY) routing and
config consistency (Valkey keyspace notifications, web-listener and TTY-host
config), a bootstrap admin still on the default email, the per-user
encryption-key invariants that crypto-shred erasure depends on (every live
user's DEK unwraps; no erased user retains one), and projection drift (a
projection that has stopped applying events, caught before retention prunes
the source events).
<!-- docref: end -->

### Exit codes

The exit code is the worst outcome, so a single boolean gate works in CI:

<!-- docref: begin src=internal/doctor/doctor.go#Report.ExitCode:91e925ce -->
| Code | Meaning |
|------|---------|
| `0`  | all clear — only `ok`/`info` findings |
| `1`  | at least one **warning** (worth fixing; not blocking) |
| `100`| at least one **critical** finding (insecure/broken — do not ship) |
| `2`  | a check could not run (exec error) — the report is incomplete; takes precedence over everything |
<!-- docref: end -->

Example gate (fail a deploy pipeline on any critical or could-not-run):

```bash
docker compose exec -T control control doctor
code=$?
if [ "$code" -ge 100 ] || [ "$code" -eq 2 ]; then
  echo "doctor found critical issues (exit $code)"; exit 1
fi
```

## Emergency projection rebuild: `rebuild-projections`

<!-- docref: begin src=cmd/control/main.go#@rebuild-subcommand:2d8f0710 -->
If a projection table is corrupted or inconsistent with the event store
(manual edit, projector bug, partial restore), the Control binary can
replay it from the event log. This is **destructive** — the selected
projection tables are truncated and rebuilt inside one transaction — so
it is deliberately CLI-only: running it requires shell access to the
Control container, and there is no remote RPC equivalent.

```bash
# rebuild every projection from the event store
docker compose exec control control rebuild-projections

# rebuild only the named targets (plus whatever cascade safety adds)
docker compose exec control control rebuild-projections users devices
```
<!-- docref: end -->

<!-- docref: begin src=cmd/control/rebuild.go#runRebuildProjections:3f101b6f -->
The command prints the resolved target list before touching anything. A
partial selection is widened automatically when a selected table's
`TRUNCATE ... CASCADE` would wipe tables owned by other targets — a
partial rebuild never destroys data it does not replay. Each target
reports events applied and events skipped (unprojectable historical
payloads) separately. Everything runs in a single transaction (one
consistent snapshot): a failure rolls back to the pre-rebuild state.
After a successful rebuild the system-role permissions are re-reconciled
from the code registry, so no Control restart is needed.

Once audit-log retention has pruned history, a plain rebuild **refuses to
run** — the surviving live log no longer contains events up to the prune
checkpoint, and replaying only it would silently lose that state. Pass
`--archive-dir <path>` (the retention archive directory, filesystem
backend) instead: the command walks the `EventLogPruned` marker chain,
verifies every sealed archive against the hash recorded in the
tamper-evident log, and rebuilds every projection from the archived
history plus the live events. Target selection is not supported with
`--archive-dir` — a restore is always a full rebuild.

Exit codes: `0` success · `1` rebuild failed (rolled back) · `2` could
not run (bad flags, unknown target, no database, pruned history without
`--archive-dir`). `--env-file <path>` works like doctor's (default
`.env`).
<!-- docref: end -->
