#!/usr/bin/env bash

set -euo pipefail

DEPLOY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DEPLOY_DIR"

[[ -f .env ]] || { printf 'missing %s/.env\n' "$DEPLOY_DIR" >&2; exit 1; }

./setup.sh
docker compose config --quiet
docker compose pull control postgres traefik
docker compose up -d --wait --remove-orphans
docker compose ps

printf 'Deployment complete. Issue a setup URL when needed with:\n'
printf '  cd %q && docker compose exec control control bootstrap-admin\n' "$DEPLOY_DIR"
