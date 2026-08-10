#!/usr/bin/env bash

set -euo pipefail
umask 077

INSTALL_DIR="${INSTALL_DIR:-/opt/power-manage}"
RELEASE_TAG="${RELEASE_TAG:-}"
GITHUB_REPOSITORY="${GITHUB_REPOSITORY:-MANCHTOOLS/power-manage-server}"

fail() { printf '[ERROR] %s\n' "$*" >&2; exit 1; }
for command_name in curl tar docker openssl; do
    command -v "$command_name" >/dev/null 2>&1 || fail "$command_name is required"
done
docker compose version >/dev/null 2>&1 || fail "the Docker Compose plugin is required"

[[ -n "${CONTROL_DOMAIN:-}" ]] || fail "set CONTROL_DOMAIN"
[[ -n "${AGENT_DOMAIN:-}" ]] || fail "set AGENT_DOMAIN"
[[ -n "${ACME_EMAIL:-}" ]] || fail "set ACME_EMAIL"

# There is deliberately no default. A branch name installs whatever that branch
# pointed at on the day it ran, which is not an installation anyone can
# reproduce, attest, or roll back to, so the release has to be named. The
# branch fallback further down is kept for an operator who names one on
# purpose; only the silent default is gone.
[[ -n "$RELEASE_TAG" ]] \
    || fail "set RELEASE_TAG to the release to install, e.g. RELEASE_TAG=v2026.08.09-rc2"

# The same rules setup.sh applies, applied before anything is downloaded. dns01
# additionally needs config/traefik-dns.env, which only exists once the tree is
# unpacked, so setup.sh below is where that one is enforced.
ACME_CHALLENGE="${ACME_CHALLENGE:-http01}"
[[ "$ACME_CHALLENGE" == http01 || "$ACME_CHALLENGE" == dns01 ]] \
    || fail "ACME_CHALLENGE must be http01 or dns01"
[[ "$ACME_CHALLENGE" != dns01 || -n "${ACME_DNS_PROVIDER:-}" ]] \
    || fail "ACME_DNS_PROVIDER is required when ACME_CHALLENGE=dns01"

# setup.sh checks the audit archive's filesystem before it generates any key
# material, so an install that stopped there leaves the directory tree and
# nothing in it. Refusing that tree would strand the operator with a half-made
# installation they cannot finish here. Refuse once generated material exists,
# which is what "already installed" means and is the state deploy.sh is for.
#
# Discovering the material rather than naming it keeps this attached to
# setup.sh: anything it writes into these three directories blocks a re-run,
# and nothing here ever deletes or rewrites what it finds. data/ is
# deliberately not consulted — the archive storage the operator was told to
# provide lives there, and so does the Traefik ACME file setup.sh touches
# before the archive check.
existing_material="$(find "$INSTALL_DIR/certs" "$INSTALL_DIR/secrets" "$INSTALL_DIR/config" \
    -mindepth 1 -print -quit 2>/dev/null || true)"
[[ -z "$existing_material" ]] \
    || fail "$INSTALL_DIR is already installed ($existing_material exists); update it with deploy.sh instead"

temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT
archive="$temporary_directory/source.tar.gz"

tag_url="https://github.com/${GITHUB_REPOSITORY}/archive/refs/tags/${RELEASE_TAG}.tar.gz"
branch_url="https://github.com/${GITHUB_REPOSITORY}/archive/refs/heads/${RELEASE_TAG}.tar.gz"
if ! curl -fsSL "$tag_url" -o "$archive"; then
    curl -fsSL "$branch_url" -o "$archive" || fail "could not download $GITHUB_REPOSITORY@$RELEASE_TAG"
fi

mkdir -p "$temporary_directory/source" "$INSTALL_DIR"
tar -xzf "$archive" -C "$temporary_directory/source"
source_root="$(find "$temporary_directory/source" -mindepth 1 -maxdepth 1 -type d -print -quit)"
[[ -f "$source_root/deploy/compose.yml" ]] || fail "release does not contain the deployment tree"
cp -R "$source_root/deploy/." "$INSTALL_DIR/"

image_tag=latest
if [[ "$RELEASE_TAG" == v* ]]; then
    image_tag="${RELEASE_TAG#v}"
fi
cat > "$INSTALL_DIR/.env" <<EOF
CONTROL_DOMAIN=$CONTROL_DOMAIN
AGENT_DOMAIN=$AGENT_DOMAIN
ACME_EMAIL=$ACME_EMAIL
ACME_CHALLENGE=$ACME_CHALLENGE
ACME_DNS_PROVIDER=${ACME_DNS_PROVIDER:-}
IMAGE_TAG=$image_tag
EOF
chmod 600 "$INSTALL_DIR/.env"

cd "$INSTALL_DIR"
./setup.sh
docker compose pull
docker compose up -d --wait

printf 'Power Manage is running. Create the one-time administrator setup URL with:\n'
printf '  cd %q && docker compose exec control control bootstrap-admin\n' "$INSTALL_DIR"
