#!/usr/bin/env bash
# Deploy smoke test — boots the REAL stack from the REAL deploy artifacts
# (setup.sh + compose.yml + valkey.conf.template + pg_hba.conf) and asserts the
# datastore layer actually comes up over mutual TLS with working ACLs.
#
# This is the test that would have caught the whole spec-32 alpha3 saga: the
# valkey uid-999 key-permission crash, the per-service ACL NOPERM (asynq:cancel
# / Traefik keyspace), the Postgres mTLS boot, and the setup.sh guided/cert
# flow. The Go integration tests use synthetic minimal configs via
# testcontainers; they prove the mechanism but never exercise these artifacts.
#
# Scope: postgres + valkey + control + indexer (gated on healthchecks) + traefik
# (log-scanned only — it needs real DNS/LE to become healthy). The gateway is
# out of scope here: it self-enrolls against control's PUBLIC URL, which needs
# real DNS — that path belongs in an end-to-end test, not a local smoke test.
#
# Usage:  ./smoke-test.sh            # uses IMAGE_TAG below (published alpha3)
#         IMAGE_TAG=mytag ./smoke-test.sh
set -euo pipefail

IMAGE_TAG="${IMAGE_TAG:-2026.08-alpha3}"
PROJECT="pm-smoke"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="$(mktemp -d)"
GATED_SERVICES=(postgres valkey control indexer)

red()   { printf '\033[0;31m%s\033[0m\n' "$*"; }
green() { printf '\033[0;32m%s\033[0m\n' "$*"; }
info()  { printf '\033[0;36m[smoke]\033[0m %s\n' "$*"; }

cleanup() {
  info "tearing down…"
  ( cd "$WORK_DIR" && docker compose -p "$PROJECT" down -v --remove-orphans >/dev/null 2>&1 || true )
  # postgres/valkey write ./data as their container uids (70/999), which a
  # non-root host user can't rm — delete via a throwaway root container first.
  docker run --rm -v "$WORK_DIR:/w" alpine:3.21 rm -rf /w/data /w/certs >/dev/null 2>&1 || true
  rm -rf "$WORK_DIR" 2>/dev/null || true
}
trap cleanup EXIT

# 1. Isolated copy of the deploy artifacts (never touches the real deploy/.env).
info "staging deploy artifacts in $WORK_DIR"
cp "$SRC_DIR/compose.yml" "$SRC_DIR/setup.sh" "$SRC_DIR/valkey.conf.template" \
   "$SRC_DIR/pg_hba.conf" "$WORK_DIR/"
cp -r "$SRC_DIR/initdb.d" "$WORK_DIR/"

# 2. A complete, valid .env (all check_env-required values, no placeholders).
cat > "$WORK_DIR/.env" <<EOF
IMAGE_TAG=${IMAGE_TAG}
CONTROL_DOMAIN=control.smoke.test
GATEWAY_DOMAIN=gateway.smoke.test
ACME_EMAIL=smoke@smoke.test
POSTGRES_PASSWORD=$(openssl rand -hex 24)
INDEXER_POSTGRES_PASSWORD=$(openssl rand -hex 24)
JWT_SECRET=$(openssl rand -hex 32)
CONTROL_ENCRYPTION_KEY=$(openssl rand -hex 32)
PM_TASK_SIGNING_KEY=$(openssl rand -hex 32)
PM_GATEWAY_ENROLL_TOKEN=$(openssl rand -base64 32)
ADMIN_EMAIL=admin@smoke.test
ADMIN_PASSWORD=$(openssl rand -hex 24)
EOF

cd "$WORK_DIR"

# 3. Real setup: CA + datastore certs + ACL passwords + rendered valkey.conf.
info "running setup.sh --no-prompt"
./setup.sh --no-prompt >setup.log 2>&1 || { red "FAIL: setup.sh errored"; tail -20 setup.log; exit 1; }

# 4. Boot the datastore core and GATE on healthchecks. `up --wait` returns
#    non-zero if any gated service never reaches healthy — this alone catches
#    the valkey key crash + Postgres mTLS boot failures.
info "docker compose up --wait ${GATED_SERVICES[*]} (IMAGE_TAG=$IMAGE_TAG)"
if ! docker compose -p "$PROJECT" up -d --wait --wait-timeout 120 "${GATED_SERVICES[@]}" >up.log 2>&1; then
  red "FAIL: a gated service did not become healthy"
  docker compose -p "$PROJECT" ps
  for s in "${GATED_SERVICES[@]}"; do echo "── $s ──"; docker compose -p "$PROJECT" logs --tail 15 "$s"; done
  exit 1
fi
green "all gated services healthy"

# 5. Traefik: start it (not gated — no DNS/LE here) so its Valkey ACL path runs.
docker compose -p "$PROJECT" up -d traefik >>up.log 2>&1 || true
sleep 8   # let control/indexer subscribe to asynq:cancel + traefik connect

# 6. The assertion that "healthy" can't make: no ACL/permission/connection
#    failure in ANY service log. This is what surfaces the NOPERM class of bug.
info "scanning logs for NOPERM / permission / connection failures"
LOGS="$(docker compose -p "$PROJECT" logs --no-color 2>&1 || true)"
BAD="$(printf '%s\n' "$LOGS" | grep -iE 'NOPERM|no permissions|permission denied|WRONGPASS|connection refused|i/o timeout|failed to configure tls' || true)"
if [[ -n "$BAD" ]]; then
  red "FAIL: datastore auth/permission errors in logs:"
  printf '%s\n' "$BAD" | head -20
  exit 1
fi

green "PASS — full datastore stack up over mTLS, ACLs clean, no permission errors"
