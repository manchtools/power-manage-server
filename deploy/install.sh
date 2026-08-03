#!/usr/bin/env bash

set -euo pipefail
umask 077

INSTALL_DIR="${INSTALL_DIR:-/opt/power-manage}"
RELEASE_TAG="${RELEASE_TAG:-main}"
GITHUB_REPOSITORY="${GITHUB_REPOSITORY:-MANCHTOOLS/power-manage-server}"

fail() { printf '[ERROR] %s\n' "$*" >&2; exit 1; }
for command_name in curl tar docker openssl; do
    command -v "$command_name" >/dev/null 2>&1 || fail "$command_name is required"
done
docker compose version >/dev/null 2>&1 || fail "the Docker Compose plugin is required"

[[ -n "${CONTROL_DOMAIN:-}" ]] || fail "set CONTROL_DOMAIN"
[[ -n "${AGENT_DOMAIN:-}" ]] || fail "set AGENT_DOMAIN"
[[ -n "${ACME_EMAIL:-}" ]] || fail "set ACME_EMAIL"
[[ ! -e "$INSTALL_DIR" ]] || fail "$INSTALL_DIR already exists; update it with deploy.sh instead"

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
IMAGE_TAG=$image_tag
EOF
chmod 600 "$INSTALL_DIR/.env"

cd "$INSTALL_DIR"
./setup.sh
docker compose pull
docker compose up -d --wait

printf 'Power Manage is running. Create the one-time administrator setup URL with:\n'
printf '  cd %q && docker compose exec control control bootstrap-admin\n' "$INSTALL_DIR"
