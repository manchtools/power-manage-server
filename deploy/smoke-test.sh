#!/usr/bin/env bash

set -euo pipefail

SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="$(mktemp -d)"
PROJECT_NAME="pm-smoke-$$"
PUBLISHED_IMAGE_TAG="${IMAGE_TAG:-}"
REQUESTED_IMAGE_TAG="${PUBLISHED_IMAGE_TAG:-smoke-$$}"
CONTROL_IMAGE="ghcr.io/manchtools/power-manage-control:$REQUESTED_IMAGE_TAG"
BUILT_IMAGE=""

compose() {
    docker compose --project-directory "$WORK_DIR" --project-name "$PROJECT_NAME" "$@"
}

cleanup() {
    local status=$?
    trap - EXIT
    if [[ $status -ne 0 ]]; then
        compose ps >&2 || true
        compose logs --no-color >&2 || true
    fi
    compose down --remove-orphans >/dev/null 2>&1 || true
    docker run --rm -v "$WORK_DIR:/work" docker.io/library/alpine:3.23 \
        sh -c 'rm -rf /work/data/postgres' >/dev/null 2>&1 || true
    if [[ -n "$BUILT_IMAGE" ]]; then
        docker image rm "$BUILT_IMAGE" >/dev/null 2>&1 || true
    fi
    rm -rf "$WORK_DIR"
    exit "$status"
}
trap cleanup EXIT

cp -R "$SOURCE_DIR/." "$WORK_DIR/"
if [[ -z "$PUBLISHED_IMAGE_TAG" ]]; then
    CGO_ENABLED=0 go -C "$SOURCE_DIR/.." build -o "$WORK_DIR/control" ./cmd/control
    docker build --build-arg BINARY=control -f "$SOURCE_DIR/Containerfile.control" \
        -t "$CONTROL_IMAGE" "$WORK_DIR"
    BUILT_IMAGE="$CONTROL_IMAGE"
fi
cat > "$WORK_DIR/.env" <<EOF
CONTROL_DOMAIN=manage.example.test
AGENT_DOMAIN=agents.example.test
ACME_EMAIL=admin@example.test
IMAGE_TAG=$REQUESTED_IMAGE_TAG
LOG_LEVEL=info
LOG_FORMAT=json
EOF

cd "$WORK_DIR"
bash ./setup.sh >/dev/null

mapfile -t services < <(compose config --services | sort)
[[ "${services[*]}" == "control postgres traefik" ]] || {
    printf 'unexpected deployment services: %s\n' "${services[*]}" >&2
    exit 1
}
if compose config | grep -q '/var/run/docker.sock'; then
    printf 'Traefik must not mount the container-engine socket\n' >&2
    exit 1
fi

compose up -d --wait postgres control

fts="$(compose exec -T postgres psql -U powermanage -d powermanage -Atc \
    "SELECT to_tsvector('simple','Power Manage') @@ plainto_tsquery('simple','manage');")"
[[ "$fts" == t ]] || { printf 'PostgreSQL FTS probe failed\n' >&2; exit 1; }

bootstrap="$(compose exec -T control control bootstrap-admin)"
[[ "$bootstrap" == *"https://manage.example.test/setup#bootstrap_token="* ]] || {
    printf 'bootstrap-admin did not issue the expected setup URL\n' >&2
    exit 1
}

go -C "$SOURCE_DIR/.." run ./cmd/rpcsurface -services ControlService > "$WORK_DIR/expected-rpcs.txt"
go -C "$SOURCE_DIR/.." run ./cmd/rpcsurface -services ControlService -invert > "$WORK_DIR/forbidden-rpcs.txt"
control_id="$(compose ps -q control)"
docker run --rm --network "container:$control_id" --user 0:0 \
    -v "$WORK_DIR:/work:ro" -v "$SOURCE_DIR/rpc-surface-probe.sh:/probe.sh:ro" \
    --entrypoint sh docker.io/curlimages/curl:8.11.1 \
    /probe.sh https://127.0.0.1:8081 /work/expected-rpcs.txt /work/forbidden-rpcs.txt

compose up -d --wait traefik

public_status="$(docker run --rm --network "container:$control_id" \
    docker.io/curlimages/curl:8.11.1 -sk -o /dev/null -w '%{http_code}' \
    --resolve manage.example.test:443:172.29.0.2 https://manage.example.test/health)"
[[ "$public_status" == 200 ]] || { printf 'public Traefik route failed\n' >&2; exit 1; }

log_canary="bootstrap-token-must-not-appear-${PROJECT_NAME}"
docker run --rm --network "container:$control_id" \
    docker.io/curlimages/curl:8.11.1 -sk -o /dev/null \
    --resolve manage.example.test:443:172.29.0.2 \
    "https://manage.example.test/health?bootstrap_token=${log_canary}"
traefik_logs="$(compose logs --no-color traefik)"
[[ "$traefik_logs" == *'"RequestMethod":"GET"'* ]] || {
    printf 'Traefik did not emit the expected access-log record\n' >&2
    exit 1
}
[[ "$traefik_logs" == *'"ServiceURL":"https://control:8081"'* ]] || {
    printf 'Traefik did not use the authenticated TLS backend\n' >&2
    exit 1
}
[[ "$traefik_logs" != *"$log_canary"* ]] || {
    printf 'Traefik access log exposed a query-string credential\n' >&2
    exit 1
}

openssl genpkey -algorithm Ed25519 -out "$WORK_DIR/certs/smoke-agent.key" >/dev/null 2>&1
openssl req -new -key "$WORK_DIR/certs/smoke-agent.key" \
    -subj '/CN=01SMOKEDEVICE0000000000000/O=Power Manage' \
    -out "$WORK_DIR/certs/smoke-agent.csr" >/dev/null 2>&1
openssl x509 -req -in "$WORK_DIR/certs/smoke-agent.csr" \
    -CA "$WORK_DIR/certs/ca.crt" -CAkey "$WORK_DIR/certs/ca.key" -CAcreateserial -days 1 \
    -extfile <(printf 'subjectAltName=URI:spiffe://power-manage/agent\nextendedKeyUsage=clientAuth\n') \
    -out "$WORK_DIR/certs/smoke-agent.crt" >/dev/null 2>&1

agent_status="$(docker run --rm --network "container:$control_id" --user 0:0 \
    -v "$WORK_DIR/certs:/certs:ro" docker.io/curlimages/curl:8.11.1 \
    -s -o /dev/null -w '%{http_code}' --max-time 10 \
    --resolve agents.example.test:443:172.29.0.2 \
    --cacert /certs/ca.crt --cert /certs/smoke-agent.crt --key /certs/smoke-agent.key \
    https://agents.example.test/health)"
[[ "$agent_status" == 200 ]] || { printf 'agent mTLS route failed\n' >&2; exit 1; }

direct_status="$(docker run --rm --network "container:$control_id" --user 0:0 \
    -v "$WORK_DIR/certs:/certs:ro" docker.io/curlimages/curl:8.11.1 \
    -s -o /dev/null -w '%{http_code}' --max-time 5 \
    --resolve agents.example.test:8082:172.30.0.3 \
    --cacert /certs/ca.crt --cert /certs/smoke-agent.crt --key /certs/smoke-agent.key \
    https://agents.example.test:8082/health 2>/dev/null || true)"
[[ "$direct_status" != 200 ]] || {
    printf 'agent listener accepted a direct connection without PROXY v2\n' >&2
    exit 1
}

printf 'PASS: three services, PostgreSQL FTS, exact RPC surface, authenticated backend TLS, query-safe logs, and isolated agent route\n'
