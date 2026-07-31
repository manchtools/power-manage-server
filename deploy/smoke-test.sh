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
# Scope: postgres + valkey + control + indexer, all gated on their
# healthchecks, plus Traefik (log-scanned). A smoke-only Compose override enables
# control's real public TLS listener with setup.sh's CA-signed control-public
# cert, adds Docker DNS aliases matching that cert, and installs the same CA into
# control's own TLS listener, so agent-facing mTLS is exercised without external
# DNS or Let's Encrypt.
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
AGENT_DOMAIN=agents.smoke.test
ACME_EMAIL=smoke@smoke.test
POSTGRES_PASSWORD=$(openssl rand -hex 24)
INDEXER_POSTGRES_PASSWORD=$(openssl rand -hex 24)
JWT_SECRET=$(openssl rand -hex 32)
CONTROL_ENCRYPTION_KEY=$(openssl rand -hex 32)
PM_TASK_SIGNING_KEY=$(openssl rand -hex 32)
ADMIN_EMAIL=admin@smoke.test
ADMIN_PASSWORD=$(openssl rand -hex 24)
EOF

# Smoke-only orchestration:
# - control serves its real public listener over TLS directly (no external
#   Traefik/LE dependency), using setup.sh's control-public cert.
# - control.smoke.test is a Docker DNS alias matching the certificate SAN
#   setup.sh stamps from CONTROL_DOMAIN.
cat > "$WORK_DIR/smoke.override.yml" <<'EOF'
services:
  # No host port exposure in CI/local smoke; everything is probed from inside
  # the Compose network. agents.smoke.test resolves to Traefik so the
  # TCP-passthrough router is exercised for real — passthrough needs no
  # certificate of its own, which is why this works without DNS or LE.
  traefik:
    ports: !reset []
    networks:
      internal:
        aliases:
          - agents.smoke.test

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

# 5b. Least-privilege confinement of the indexer (spec 32 A2): it owns the
# search namespaces and must not reach anything else in the keyspace.
#
# The pm-gateway CRL probes that used to sit here are gone with the CRL and the
# user that read it — revocations live in control's own database now. The
# indexer half is NOT gateway-related and stays: it is the only assertion in
# this block about a service that still exists, and deleting the block wholesale
# would have dropped it silently.
for k in pm:device:smoke-probe smoke-probe-unnamespaced; do
  IX_WRITE="$(compose exec -T -e REDISCLI_AUTH="$VALKEY_INDEXER_PASSWORD" valkey \
    valkey-cli "${VALKEY_TLS_ARGS[@]}" --user pm-indexer SET "$k" v 2>&1 || true)"
  [[ "$IX_WRITE" == *NOPERM* ]] || { red "FAIL: pm-indexer can write $k outside its namespace (spec 32 A2)"; printf '%s\n' "$IX_WRITE"; exit 1; }
done
green "pm-indexer is confined to its search namespaces"

# 5b. RPC SURFACE: the assertion no unit test can make — does the RUNNING
#     listener serve exactly the procedures that belong on it? Every other
#     surface guard in the tree checks code against code. This checks a real
#     process on a real listener.
#
#     Scoped PER LISTENER, not globally: the contract's services live in
#     different processes on purpose (ControlService on control's public
#     listener, InternalService on its mTLS listener, AgentService wherever the
#     agent stream terminates, DeviceAuthService on the agent's own enrollment
#     socket). A global list would report the other processes' services as
#     missing here, and could not express the property that matters — that a
#     service is NOT reachable on a listener it does not belong to.
info "probing the served RPC surface of control's public listener"
command -v go >/dev/null 2>&1 || { red "FAIL: go toolchain unavailable — cannot derive the expected RPC surface"; exit 1; }

# Expected: exactly ControlService on this listener.
go -C "$SRC_DIR/.." run ./cmd/rpcsurface -services ControlService \
  > "$WORK_DIR/expected-rpcs.txt" 2>"$WORK_DIR/rpcsurface.err" || {
  red "FAIL: could not derive the expected RPC surface"; cat "$WORK_DIR/rpcsurface.err"; exit 1; }

# Must NOT be served here, from two sources:
#   - every other live service (exposure: AgentService must never be reachable
#     on the public listener, which requires no client certificate)
#   - the procedures spec 41 removed from the contract entirely
go -C "$SRC_DIR/.." run ./cmd/rpcsurface -services ControlService -invert \
  > "$WORK_DIR/forbidden-rpcs.txt" 2>>"$WORK_DIR/rpcsurface.err" || {
  red "FAIL: could not derive the forbidden RPC surface"; cat "$WORK_DIR/rpcsurface.err"; exit 1; }
[[ -f "$SRC_DIR/removed-rpcs.txt" ]] && cat "$SRC_DIR/removed-rpcs.txt" >> "$WORK_DIR/forbidden-rpcs.txt"

# --user 0:0 because WORK_DIR is a mktemp dir (mode 700) owned by the host user;
# the curl image's unprivileged default cannot traverse it. --entrypoint sh
# because the image's entrypoint is curl itself.
CONTROL_CID="$(compose ps -q control)"
[[ -n "$CONTROL_CID" ]] || { red "FAIL: control container not found for the RPC probe"; exit 1; }
docker run --rm --network "container:${CONTROL_CID}" --user 0:0 \
  -v "$WORK_DIR:/w:ro" -v "$SRC_DIR/rpc-surface-probe.sh:/probe.sh:ro" \
  --entrypoint sh docker.io/curlimages/curl:8.11.1 \
  /probe.sh https://localhost:8081 /w/expected-rpcs.txt /w/forbidden-rpcs.txt \
  || { red "FAIL: served RPC surface does not match the contract"; exit 1; }

# 6. Traefik: start it (not gated — no DNS/LE here).
compose up -d traefik >>up.log 2>&1 || true
sleep 8   # let control/indexer subscribe to asynq:cancel + traefik pick up labels

# 6b. AGENT ROUTE: can an agent actually reach the stream through the deployed
#     edge? Every other check in this file, and every Go test, stops at control's
#     own listener. This one starts where an agent starts — the hostname control
#     hands out at registration — and goes through Traefik.
#
#     It exists because the stack shipped in a state where it could not: the
#     registration URL pointed at the web host, which Traefik terminates and
#     routes to :8081 (no AgentService, no client-certificate request), while the
#     agent listener on :8082 had no route at all and control.crt carried no
#     public SAN. Unit tests were green throughout; nothing here could see it.
info "probing the agent route: registration URL -> Traefik SNI -> control mTLS listener"

# The URL control actually hands to agents, read from the running container
# rather than restated here — if it is ever repointed at the web host again,
# this probe follows it there and fails, which is the property under test.
AGENT_URL="$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$(compose ps -q control)" \
  | sed -n 's/^CONTROL_AGENT_URL=//p')"
[[ -n "$AGENT_URL" ]] || { red "FAIL: control has no CONTROL_AGENT_URL — agents receive no endpoint at registration"; exit 1; }
AGENT_HOST="${AGENT_URL#https://}"; AGENT_HOST="${AGENT_HOST%%/*}"
info "  registration hands agents: $AGENT_URL"

# A CA-signed client certificate: the agent listener requires one, so this is
# also what distinguishes it from the public listener.
openssl ecparam -genkey -name prime256v1 -noout -out certs/smoke-agent.key 2>/dev/null
openssl req -new -key certs/smoke-agent.key -subj "/CN=01SMOKEDEVICE0000000000000/O=Power Manage" \
  -out certs/smoke-agent.csr 2>/dev/null
openssl x509 -req -in certs/smoke-agent.csr -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial \
  -days 1 -extfile <(printf "subjectAltName=URI:spiffe://power-manage/agent\nauthorityKeyIdentifier=keyid:always") \
  -out certs/smoke-agent.crt 2>/dev/null
chmod 644 certs/smoke-agent.key certs/smoke-agent.crt

CONTROL_CID="$(compose ps -q control)"
[[ -n "$CONTROL_CID" ]] || { red "FAIL: control container not found for the agent-route probe"; exit 1; }

# Positive: through Traefik, with a client cert, verifying control's identity as
# the name the agent dialled. This passes only if ALL of it holds — the TCP
# router matched the SNI, passthrough left the handshake to control, control.crt
# carries the agent host as a SAN, and the mTLS listener accepted the cert.
AGENT_PROBE="$(docker run --rm --network "container:${CONTROL_CID}" --user 0:0 \
  -v "$WORK_DIR/certs:/c:ro" --entrypoint curl docker.io/curlimages/curl:8.11.1 \
  -sS -o /dev/null -w '%{http_code}' --max-time 20 \
  --cacert /c/ca.crt --cert /c/smoke-agent.crt --key /c/smoke-agent.key \
  "https://${AGENT_HOST}/health" 2>&1 || true)"
if [[ "$AGENT_PROBE" != "200" ]]; then
  red "FAIL: an agent cannot reach the stream endpoint it is given at registration"
  red "      dialled https://${AGENT_HOST}/health through Traefik, got: ${AGENT_PROBE}"
  compose logs --tail 20 traefik || true
  exit 1
fi

# Negative control: the same URL without a client certificate must NOT succeed.
# Without this the positive result could come from any plain HTTPS listener —
# which is exactly the misconfiguration being guarded against.
#
# This deliberately provokes a TLS handshake error in control's log, so the
# boundary is recorded first: step 7 scans everything BEFORE this point, and the
# error itself is asserted below instead of being filtered away.
NEG_PROBE_START="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
sleep 1
NOCERT_PROBE="$(docker run --rm --network "container:${CONTROL_CID}" --user 0:0 \
  -v "$WORK_DIR/certs:/c:ro" --entrypoint curl docker.io/curlimages/curl:8.11.1 \
  -sS -o /dev/null -w '%{http_code}' --max-time 20 \
  --cacert /c/ca.crt "https://${AGENT_HOST}/health" 2>&1 || true)"
if [[ "$NOCERT_PROBE" == "200" ]]; then
  red "FAIL: ${AGENT_HOST} served /health WITHOUT a client certificate"
  red "      the agent host must reach the mTLS listener, not the public one"
  exit 1
fi

# ...and prove the refusal came from CONTROL, not from Traefik or a dead port.
# A connection that never arrived would also produce a non-200, so without this
# the negative control would pass for the wrong reason.
sleep 2
NEG_LOGS="$(compose logs --no-color --since "$NEG_PROBE_START" control 2>&1 || true)"
if ! printf '%s\n' "$NEG_LOGS" | grep -q "client didn't provide a certificate"; then
  red "FAIL: no client-certificate refusal in control's log — the certificate-less"
  red "      probe did not reach control's mTLS listener, so its failure proves nothing"
  printf '%s\n' "$NEG_LOGS"
  exit 1
fi
green "agent route works: ${AGENT_HOST} -> Traefik passthrough -> control mTLS listener (client cert required)"

# 7. The assertion that "healthy" can't make: no ACL, permission, connection,
#    or TLS-identity failure in ANY service log. This catches NOPERM as well as
#    a dial-address/certificate-name mismatch (TLS handshake / bad certificate).
# Bounded at NEG_PROBE_START so the handshake error the negative control just
# provoked on purpose is not rescanned as a fault. It is asserted above; a
# blanket filter here would instead blind this scan to real ones.
info "scanning logs for ACL / permission / connection / TLS failures"
LOGS="$(compose logs --no-color --until "$NEG_PROBE_START" 2>&1 || true)"
BAD="$(printf '%s\n' "$LOGS" | grep -iE 'NOPERM|no permissions|permission denied|WRONGPASS|connection refused|i/o timeout|failed to configure tls|TLS handshake error|bad certificate' || true)"
if [[ -n "$BAD" ]]; then
  red "FAIL: auth/permission/connection/TLS errors in logs:"
  printf '%s\n' "$BAD" | head -20
  exit 1
fi

green "PASS — full stack is healthy; mTLS/ACL/TLS logs clean; served RPC surface matches the contract"
