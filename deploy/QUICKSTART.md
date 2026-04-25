# Power Manage Server — Quickstart

One-line install on a fresh Linux host with Docker + the compose plugin already installed:

```bash
curl -fsSL https://raw.githubusercontent.com/MANCHTOOLS/power-manage-server/main/deploy/install.sh | sudo bash
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
git clone https://github.com/MANCHTOOLS/power-manage-server.git
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
