#!/usr/bin/env bash

set -euo pipefail

SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="$(mktemp -d)"
ARCHIVE_DIR=""
PROJECT_NAME="pm-smoke-$$"
PUBLISHED_IMAGE_TAG="${IMAGE_TAG:-}"
REQUESTED_IMAGE_TAG="${PUBLISHED_IMAGE_TAG:-smoke-$$}"
CONTROL_IMAGE="ghcr.io/manchtools/power-manage-control:$REQUESTED_IMAGE_TAG"
BUILT_IMAGE=""

# The archive has to hold control's audit anchors and archived chain prefixes
# plus the one SQLite backup this run takes and verifies. Below this a tmpfs
# fails partway through with ENOSPC inside a health check, which says nothing
# about the release under test.
ARCHIVE_MINIMUM_KIB=16384

# Compose substitutes from the process environment before any env file, and CI
# exports IMAGE_TAG as an empty string, which resolves compose.yml's
# ${IMAGE_TAG:-latest} to the stale published image instead of this run's tag.
# Export the tag this run actually uses so environment and .env agree.
export IMAGE_TAG="$REQUESTED_IMAGE_TAG"

compose() {
    docker compose --project-directory "$WORK_DIR" --project-name "$PROJECT_NAME" \
        --env-file "$WORK_DIR/.env" "$@"
}

# Control and backup.sh write into the state and archive directories as root,
# and the host user running this script cannot unlink what they leave in the
# directories root creates underneath. Empty those from a container instead.
remove_root_owned_content() {
    local directory="$1"
    [[ -d "$directory" ]] || return 0
    docker run --rm -v "$directory:/target" docker.io/library/alpine:3.23 \
        find /target -mindepth 1 -delete >/dev/null 2>&1 || true
}

cleanup() {
    local status=$?
    trap - EXIT
    if [[ $status -ne 0 ]]; then
        compose ps >&2 || true
        compose logs --no-color >&2 || true
    fi
    compose down --remove-orphans >/dev/null 2>&1 || true
    remove_root_owned_content "$WORK_DIR/data/control"
    # The archive is a filesystem of its own outside $WORK_DIR, so it needs a
    # mount of its own: reached through $WORK_DIR it is only a symlink, and
    # what that symlink names does not exist inside the container.
    if [[ -n "$ARCHIVE_DIR" ]]; then
        remove_root_owned_content "$ARCHIVE_DIR"
        rmdir "$ARCHIVE_DIR" 2>/dev/null || true
    fi
    if [[ -n "$BUILT_IMAGE" ]]; then
        docker image rm "$BUILT_IMAGE" >/dev/null 2>&1 || true
    fi
    rm -rf "$WORK_DIR"
    exit "$status"
}
trap cleanup EXIT

# Control refuses to boot when the audit archive shares a filesystem with the
# database, and setup.sh refuses to render such a configuration, so this
# deployment needs two filesystems rather than the single $WORK_DIR. /dev/shm
# is a tmpfs on every Linux and is always a different mount from the one behind
# mktemp; the archive lives there and data/backups points at it. A symlink is
# one of the two arrangements setup.sh accepts, and Docker resolves it the same
# way when it binds the directory into control.
#
# There is deliberately no fallback to $WORK_DIR. Falling back would render a
# deployment that cannot start and reduce this release gate to a --wait timeout
# with nothing naming the cause.
provision_archive_storage() {
    local available
    [[ -d /dev/shm && -w /dev/shm ]] || {
        printf 'the audit archive needs a filesystem separate from %s, and /dev/shm is not writable\n' \
            "$WORK_DIR" >&2
        exit 1
    }
    available="$(df -Pk /dev/shm | awk 'NR == 2 { print $4 }')"
    [[ "$available" =~ ^[0-9]+$ ]] || {
        printf 'cannot read the free space on /dev/shm, which has to hold the audit archive\n' >&2
        exit 1
    }
    (( available >= ARCHIVE_MINIMUM_KIB )) || {
        printf '/dev/shm has %s KiB free; the audit archive needs at least %s KiB\n' \
            "$available" "$ARCHIVE_MINIMUM_KIB" >&2
        exit 1
    }
    ARCHIVE_DIR="$(mktemp -d /dev/shm/pm-smoke-archive-XXXXXX)"
    mkdir -p "$WORK_DIR/data"
    rm -rf -- "$WORK_DIR/data/backups"
    ln -s "$ARCHIVE_DIR" "$WORK_DIR/data/backups"
}

# The value of one variable in the rendered configuration. A name rendered zero
# times, or twice, fails here rather than yielding an empty string the caller
# would go on to compare.
control_env_value() {
    local name="$1" matches value
    matches="$(grep -c "^$name=" "$WORK_DIR/config/control.env" || true)"
    [[ "$matches" == 1 ]] || {
        printf '%s is set %s times in the rendered control.env, want once\n' "$name" "$matches" >&2
        return 1
    }
    value="$(sed -n "s|^$name=||p" "$WORK_DIR/config/control.env")"
    [[ -n "$value" ]] || {
        printf '%s is empty in the rendered control.env\n' "$name" >&2
        return 1
    }
    printf '%s\n' "$value"
}

# The host path Compose will bind onto a container path, read from the resolved
# configuration rather than from compose.yml's text, so it is the mount control
# actually gets. A container path bound zero times, or more than once, fails
# here instead of leaving the comparison below testing nothing.
host_mount_for() {
    local target="$1"
    compose config | awk -v target="$target" '
        $1 == "-" { source = "" }
        $1 == "source:" { source = $2 }
        $1 == "target:" && $2 == target && source != "" { print source; matches++ }
        END { exit matches == 1 ? 0 : 1 }
    ' || {
        printf 'compose does not bind exactly one host path onto %s\n' "$target" >&2
        return 1
    }
}

# Control compares these two filesystems at startup and refuses to run when
# they match, so a colliding pair would spend the whole of `compose up --wait`
# on a container that was never going to become healthy. Both paths are derived
# from the rendered configuration and the resolved mounts, so a path that moves
# in setup.sh or is remounted in compose.yml stays covered instead of escaping
# a hardcoded pair.
assert_archive_isolated() {
    local database_path archive_path database archive
    database_path="$(control_env_value POWER_MANAGE_DATABASE_PATH)"
    archive_path="$(control_env_value POWER_MANAGE_BACKUP_PATH)"
    database="$(host_mount_for "$(dirname "$database_path")")"
    archive="$(host_mount_for "$archive_path")"
    [[ "$(stat -L -c '%d' "$database")" != "$(stat -L -c '%d' "$archive")" ]] || {
        printf 'the audit archive shares a filesystem with the database and control will not start:\n    database %s\n    archive  %s\n' \
            "$database" "$archive" >&2
        return 1
    }
}

cp -R "$SOURCE_DIR/." "$WORK_DIR/"
provision_archive_storage
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
EOF

cd "$WORK_DIR"
bash ./setup.sh >/dev/null
assert_archive_isolated

mapfile -t services < <(compose config --services | sort)
[[ "${services[*]}" == "control traefik" ]] || {
    printf 'unexpected deployment services: %s\n' "${services[*]}" >&2
    exit 1
}
if compose config | grep -q '/var/run/docker.sock'; then
    printf 'Traefik must not mount the container-engine socket\n' >&2
    exit 1
fi

compose up -d --wait control

schema_version="$(compose exec -T control sqlite3 /var/lib/power-manage/state/control.db 'PRAGMA user_version;')"
[[ "$schema_version" == 1 ]] || { printf 'SQLite schema probe failed\n' >&2; exit 1; }
fts="$(compose exec -T control sqlite3 /var/lib/power-manage/state/control.db \
    "SELECT count(*) FROM sqlite_schema WHERE name = 'search_fts';")"
[[ "$fts" == 1 ]] || { printf 'SQLite FTS5 probe failed\n' >&2; exit 1; }

COMPOSE_PROJECT_NAME="$PROJECT_NAME" bash ./backup.sh >/dev/null
if ! compose exec -T control control backup-status >/dev/null; then
    printf 'verified backup was not reported as fresh\n' >&2
    exit 1
fi

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

printf 'PASS: two services, isolated audit archive, verified SQLite backup, FTS5, exact RPC surface, authenticated backend TLS, query-safe logs, and isolated agent route\n'
