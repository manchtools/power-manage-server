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
# Scope: postgres + valkey + control + indexer + gateway, all gated on their
# healthchecks, plus Traefik (log-scanned). A smoke-only Compose override enables
# control's real public TLS listener with setup.sh's CA-signed control-public
# cert, adds Docker DNS aliases matching that cert, and installs the same CA into
# the gateway image's system trust. This exercises real gateway self-enrollment
# without external DNS or Let's Encrypt.
#
# Usage:  ./smoke-test.sh            # uses IMAGE_TAG below (published alpha3)
#         IMAGE_TAG=mytag ./smoke-test.sh
set -euo pipefail

IMAGE_TAG="${IMAGE_TAG:-2026.08-alpha3}"
PROJECT="pm-smoke"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="$(mktemp -d)"
GATED_SERVICES=(postgres valkey control indexer gateway)

red()   { printf '\033[0;31m%s\033[0m\n' "$*"; }
green() { printf '\033[0;32m%s\033[0m\n' "$*"; }
info()  { printf '\033[0;36m[smoke]\033[0m %s\n' "$*"; }

compose() {
  docker compose -p "$PROJECT" -f "$WORK_DIR/compose.yml" -f "$WORK_DIR/smoke.override.yml" "$@"
}

cleanup() {
  info "tearing down…"
  compose down -v --remove-orphans >/dev/null 2>&1 || true
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

# Smoke-only orchestration:
# - control serves the real public GatewayAuthService over TLS directly (no
#   external Traefik/LE dependency), using setup.sh's control-public cert.
# - control.smoke.test / gateway.smoke.test are Docker DNS aliases matching the
#   certificate SANs setup.sh stamps from CONTROL_DOMAIN/GATEWAY_DOMAIN.
# - the published gateway image normally trusts public roots for enrollment; the
#   smoke override installs setup.sh's internal CA into its system trust first.
cat > "$WORK_DIR/smoke.override.yml" <<'EOF'
services:
  # No host port exposure in CI/local smoke: Traefik still runs and exercises
  # its real Redis-provider mTLS/ACL path entirely inside the Compose network.
  traefik:
    ports: !reset []

  control:
    environment:
      - CONTROL_TLS_ENABLED=true
      - CONTROL_TLS_CERT=/certs/control-public.crt
      - CONTROL_TLS_KEY=/certs/control-public.key
    healthcheck:
      test: ["CMD", "wget", "--no-check-certificate", "-q", "--spider", "https://localhost:8081/health"]
    networks:
      internal:
        aliases:
          - control.smoke.test

  gateway:
    entrypoint:
      - "sh"
      - "-c"
      - "cp /certs/ca.crt /usr/local/share/ca-certificates/power-manage-smoke.crt && update-ca-certificates >/dev/null && exec /usr/local/bin/gateway"
    environment:
      - GATEWAY_CONTROL_ENROLL_URL=https://control.smoke.test:8081
      - GATEWAY_INTERNAL_URL=https://gateway.smoke.test:8080
    networks:
      internal:
        aliases:
          - gateway.smoke.test
EOF

cd "$WORK_DIR"

# 3. Real setup: CA + datastore certs + ACL passwords + rendered valkey.conf.
info "running setup.sh --no-prompt"
./setup.sh --no-prompt >setup.log 2>&1 || { red "FAIL: setup.sh errored"; tail -20 setup.log; exit 1; }

# 4. Boot the datastore core and GATE on healthchecks. `up --wait` returns
#    non-zero if any gated service never reaches healthy — this alone catches
#    the valkey key crash + Postgres mTLS boot failures.
info "docker compose up --wait ${GATED_SERVICES[*]} (IMAGE_TAG=$IMAGE_TAG)"
if ! compose up -d --wait --wait-timeout 120 "${GATED_SERVICES[@]}" >up.log 2>&1; then
  red "FAIL: a gated service did not become healthy"
  compose ps
  for s in "${GATED_SERVICES[@]}"; do echo "── $s ──"; compose logs --tail 15 "$s"; done
  exit 1
fi
green "all gated services healthy"

# 5. Exercise pm-control's REAL search ACL with REAL indexed state, not merely
# startup health or an empty index. Valkey Search checks the selected index's
# configured document PREFIX (`search:*`) when matching documents; querying an
# empty index can return 0 without surfacing a missing prefix grant. Seed one
# production-shaped action hash as pm-indexer, then require pm-control to find it.
set -a
source ./.env
set +a
VALKEY_TLS_ARGS=(--tls --cert /certs/valkey.crt --key /tmp/valkey.key --cacert /certs/ca.crt --no-auth-warning)
compose exec -T -e REDISCLI_AUTH="$VALKEY_INDEXER_PASSWORD" valkey \
  valkey-cli "${VALKEY_TLS_ARGS[@]}" --user pm-indexer HSET search:action:acl-probe \
  name aclprobe description "deployment ACL probe" type FILE is_compliance false \
  assigned false created_at 1 updated_at 1 >/dev/null

# Indexing is asynchronous; retry briefly until the indexer-visible query sees
# the document, then issue the same query as pm-control. A no-result response is
# a test setup failure, not success.
INDEXER_SEARCH=""
for _ in $(seq 1 20); do
  INDEXER_SEARCH="$(compose exec -T -e REDISCLI_AUTH="$VALKEY_INDEXER_PASSWORD" valkey \
    valkey-cli "${VALKEY_TLS_ARGS[@]}" --user pm-indexer FT.SEARCH idx:actions '@name:aclprobe' LIMIT 0 1 2>&1 || true)"
  [[ "$INDEXER_SEARCH" == *search:action:acl-probe* ]] && break
  sleep 0.25
done
[[ "$INDEXER_SEARCH" == *search:action:acl-probe* ]] || { red "FAIL: search probe document was not indexed"; printf '%s\n' "$INDEXER_SEARCH"; exit 1; }

SEARCH_OUT="$(compose exec -T -e REDISCLI_AUTH="$VALKEY_CONTROL_PASSWORD" valkey \
  valkey-cli "${VALKEY_TLS_ARGS[@]}" --user pm-control FT.SEARCH idx:actions '@name:aclprobe' LIMIT 0 1 2>&1 || true)"
if [[ "$SEARCH_OUT" == *NOPERM* || "$SEARCH_OUT" != *search:action:acl-probe* ]]; then
  red "FAIL: pm-control cannot execute the production FT.SEARCH path:"
  printf '%s\n' "$SEARCH_OUT"
  exit 1
fi

# Widening search access must not accidentally make pm-control unrestricted.
FORBIDDEN_OUT="$(compose exec -T -e REDISCLI_AUTH="$VALKEY_CONTROL_PASSWORD" valkey \
  valkey-cli "${VALKEY_TLS_ARGS[@]}" --user pm-control GET forbidden:acl-probe 2>&1 || true)"
[[ "$FORBIDDEN_OUT" == *NOPERM* ]] || { red "FAIL: pm-control can read an unrelated key"; exit 1; }
DANGEROUS_OUT="$(compose exec -T -e REDISCLI_AUTH="$VALKEY_CONTROL_PASSWORD" valkey \
  valkey-cli "${VALKEY_TLS_ARGS[@]}" --user pm-control FLUSHALL 2>&1 || true)"
[[ "$DANGEROUS_OUT" == *NOPERM* ]] || { red "FAIL: pm-control can run FLUSHALL"; exit 1; }
green "pm-control found an indexed search document; unrelated keys + dangerous commands remain denied"

# 6. Traefik: start it (not gated — no DNS/LE here) so its Valkey ACL path runs.
compose up -d traefik >>up.log 2>&1 || true
sleep 8   # let control/indexer subscribe to asynq:cancel + traefik connect

# 7. The assertion that "healthy" can't make: no ACL, permission, connection,
#    or TLS-identity failure in ANY service log. This catches NOPERM as well as
#    a dial-address/certificate-name mismatch (TLS handshake / bad certificate).
info "scanning logs for ACL / permission / connection / TLS failures"
LOGS="$(compose logs --no-color 2>&1 || true)"
BAD="$(printf '%s\n' "$LOGS" | grep -iE 'NOPERM|no permissions|permission denied|WRONGPASS|connection refused|i/o timeout|failed to configure tls|TLS handshake error|bad certificate' || true)"
if [[ -n "$BAD" ]]; then
  red "FAIL: auth/permission/connection/TLS errors in logs:"
  printf '%s\n' "$BAD" | head -20
  exit 1
fi

green "PASS — full stack including gateway enrollment is healthy; mTLS/ACL/TLS logs clean"
