#!/usr/bin/env bash

set -euo pipefail

DEPLOY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# The single expected control.env surface. Every name assertion derives from
# this list, so an added, removed, or duplicated variable is caught once.
CONTROL_ENV_VARIABLES=(
    POWER_MANAGE_PUBLIC_LISTEN
    POWER_MANAGE_AGENT_LISTEN
    POWER_MANAGE_PUBLIC_BASE_URL
    POWER_MANAGE_AGENT_URL
    POWER_MANAGE_TERMINAL_URL
    POWER_MANAGE_CORS_ORIGINS
    POWER_MANAGE_TERMINAL_ORIGINS
    POWER_MANAGE_TRUSTED_PROXIES
    POWER_MANAGE_AGENT_PROXY_SOURCES
    POWER_MANAGE_LOG_LEVEL
    POWER_MANAGE_LOG_FORMAT
    POWER_MANAGE_CERTIFICATE_VALIDITY
    POWER_MANAGE_HEARTBEAT_INTERVAL
    POWER_MANAGE_AUDIT_RETENTION
    POWER_MANAGE_ARTIFACT_PATH
    POWER_MANAGE_DATABASE_PATH
    POWER_MANAGE_BACKUP_PATH
    POWER_MANAGE_BACKUP_MAX_LAG
    POWER_MANAGE_WEBHOOK_URL
    POWER_MANAGE_CA_CERT_FILE
    POWER_MANAGE_CA_KEY_FILE
    POWER_MANAGE_AGENT_TLS_CERT_FILE
    POWER_MANAGE_AGENT_TLS_KEY_FILE
    POWER_MANAGE_PUBLIC_TLS_CERT_FILE
    POWER_MANAGE_PUBLIC_TLS_KEY_FILE
    POWER_MANAGE_ENCRYPTION_KEY_FILE
    POWER_MANAGE_SESSION_SIGNING_KEY_FILE
    POWER_MANAGE_SEALING_KEY_FILE
)

# Every fixture models a deployment that can actually start, archive storage
# included. Without it setup.sh would stop at the archive check and each
# negative test below would pass for a reason it does not name.
new_fixture() {
    local directory="$1" control_domain="$2" agent_domain="$3"
    mkdir -p "$directory"
    cat > "$directory/.env" <<EOF
CONTROL_DOMAIN=$control_domain
AGENT_DOMAIN=$agent_domain
ACME_EMAIL=admin@example.test
EOF
    link_archive_filesystem "$directory"
}

# Control refuses to boot when the audit archive shares a filesystem with the
# database, so a fixture needs a second real filesystem rather than a stubbed
# comparison. /dev/shm is a tmpfs on every Linux and is always a different
# mount from the one holding a mktemp directory; the assertion proves that for
# this machine instead of assuming it. The symlink is one of the two
# arrangements setup.sh accepts, and Docker resolves it the same way when it
# binds the directory into the container.
link_archive_filesystem() {
    local directory="$1" archive
    archive="$(mktemp -d "$ARCHIVE_ROOT/XXXXXX")"
    mkdir -p "$directory/data"
    ln -s "$archive" "$directory/data/backups"
    [[ "$(stat -L -c '%d' "$directory/data/backups")" != "$(stat -L -c '%d' "$directory")" ]] || {
        printf 'fixture cannot model two filesystems: %s and %s share one\n' "$archive" "$directory" >&2
        return 1
    }
}

# The rendered file is consumed verbatim by Compose as an env file, so assert
# whole lines: a name that merely appears as a substring is not a setting.
assert_env_line() {
    local file="$1" line="$2"
    grep -Fxq -- "$line" "$file" || {
        printf 'missing %s in %s\n' "$line" "$file" >&2
        return 1
    }
}

# Every rendered line must name exactly one expected variable, and every
# expected variable must be rendered exactly once. Taking the name from every
# line rather than only from assignment-shaped lines also rejects stray output.
assert_env_variable_set() {
    local file="$1" expected actual
    expected="$(printf '%s\n' "${CONTROL_ENV_VARIABLES[@]}" | LC_ALL=C sort)"
    actual="$(cut -d= -f1 < "$file" | LC_ALL=C sort)"
    [[ "$expected" == "$actual" ]] || {
        printf 'unexpected control.env variables:\n%s\n' \
            "$(diff <(printf '%s\n' "$expected") <(printf '%s\n' "$actual") || true)" >&2
        return 1
    }
}

# The value of one rendered variable. A name rendered zero times, or twice,
# fails here rather than yielding an empty string the caller would compare.
env_value() {
    local file="$1" name="$2" matches value
    matches="$(grep -c "^$name=" "$file" || true)"
    [[ "$matches" == 1 ]] || {
        printf '%s is set %s times in %s, want once\n' "$name" "$matches" "$file" >&2
        return 1
    }
    value="$(sed -n "s|^$name=||p" "$file")"
    [[ -n "$value" ]] || {
        printf '%s is empty in %s\n' "$name" "$file" >&2
        return 1
    }
    printf '%s\n' "$value"
}

# The host directory Compose bind-mounts onto a container path. Reading it out
# of compose.yml keeps the assertion attached to the deployment: a mount that
# moves, disappears, or is declared twice fails here instead of leaving the
# filesystem comparison below testing a path nothing is mounted on.
host_mount_for() {
    local container_path="$1" directory="$2" matches source
    matches="$(grep -cE "^ +- \./[^:]+:${container_path}:" "$DEPLOY_DIR/compose.yml" || true)"
    [[ "$matches" == 1 ]] || {
        printf 'compose.yml bind-mounts %s %s times, want once\n' "$container_path" "$matches" >&2
        return 1
    }
    source="$(sed -nE "s|^ +- \./([^:]+):${container_path}:.*$|\1|p" "$DEPLOY_DIR/compose.yml")"
    printf '%s\n' "$directory/$source"
}

# The rendered configuration must never place the audit archive on the
# filesystem holding the database, because control refuses to start when it
# does. Both paths are read back out of the rendered file and translated
# through compose.yml's bind mounts, so moving either one in setup.sh, or
# remounting it in compose.yml, stays covered instead of escaping a hardcoded
# pair.
assert_archive_isolated() {
    local config="$1" directory="$2"
    local database_path archive_path database archive
    database_path="$(env_value "$config" POWER_MANAGE_DATABASE_PATH)"
    archive_path="$(env_value "$config" POWER_MANAGE_BACKUP_PATH)"
    database="$(host_mount_for "$(dirname "$database_path")" "$directory")"
    archive="$(host_mount_for "$archive_path" "$directory")"
    [[ "$(stat -L -c '%d' "$database")" != "$(stat -L -c '%d' "$archive")" ]] || {
        printf 'rendered config puts the audit archive on the database filesystem: %s and %s\n' \
            "$database" "$archive" >&2
        return 1
    }
}

run_setup() {
    local directory="$1"
    (
        # shellcheck disable=SC1091
        source "$DEPLOY_DIR/setup.sh"
        # These globals are consumed by the sourced setup functions.
        # shellcheck disable=SC2034
        SCRIPT_DIR="$directory"
        # shellcheck disable=SC2034
        CERTS_DIR="$directory/certs"
        # shellcheck disable=SC2034
        CONFIG_DIR="$directory/config"
        # shellcheck disable=SC2034
        SECRETS_DIR="$directory/secrets"
        # shellcheck disable=SC2034
        DATA_DIR="$directory/data"
        main
    )
}

test_secure_idempotent_setup() {
    local directory="$1"
    new_fixture "$directory" manage.example.test agents.example.test
    run_setup "$directory" >/dev/null

    [[ "$(stat -c '%a' "$directory/secrets/encryption.key")" == 600 ]]
    [[ "$(stat -c '%a' "$directory/certs/ca.key")" == 600 ]]

    local config="$directory/config/control.env"
    [[ -f "$config" ]]
    [[ "$(stat -c '%a' "$config")" == 600 ]]
    # Control is configured entirely by the environment; no file is rendered.
    [[ ! -e "$directory/config/control.json" ]]
    assert_env_variable_set "$config"
    assert_env_line "$config" 'POWER_MANAGE_PUBLIC_LISTEN=0.0.0.0:8081'
    assert_env_line "$config" 'POWER_MANAGE_AGENT_LISTEN=172.30.0.3:8082'
    assert_env_line "$config" 'POWER_MANAGE_PUBLIC_BASE_URL=https://manage.example.test'
    assert_env_line "$config" 'POWER_MANAGE_AGENT_URL=https://agents.example.test'
    assert_env_line "$config" 'POWER_MANAGE_TERMINAL_URL=wss://manage.example.test/terminal'
    assert_env_line "$config" 'POWER_MANAGE_CORS_ORIGINS=https://manage.example.test'
    assert_env_line "$config" 'POWER_MANAGE_TERMINAL_ORIGINS=manage.example.test'
    assert_env_line "$config" 'POWER_MANAGE_TRUSTED_PROXIES=172.29.0.2'
    assert_env_line "$config" 'POWER_MANAGE_AGENT_PROXY_SOURCES=172.30.0.2'
    # Both defaults are rendered by setup.sh; the fixture .env never set them.
    assert_env_line "$config" 'POWER_MANAGE_LOG_LEVEL=info'
    assert_env_line "$config" 'POWER_MANAGE_LOG_FORMAT=json'
    assert_env_line "$config" 'POWER_MANAGE_CERTIFICATE_VALIDITY=8760h'
    assert_env_line "$config" 'POWER_MANAGE_HEARTBEAT_INTERVAL=30s'
    assert_env_line "$config" 'POWER_MANAGE_AUDIT_RETENTION=2160h'
    assert_env_line "$config" 'POWER_MANAGE_ARTIFACT_PATH=/var/lib/power-manage/artifacts'
    assert_env_line "$config" 'POWER_MANAGE_DATABASE_PATH=/var/lib/power-manage/state/control.db'
    assert_env_line "$config" 'POWER_MANAGE_BACKUP_PATH=/var/lib/power-manage/backups'
    assert_env_line "$config" 'POWER_MANAGE_BACKUP_MAX_LAG=26h'
    assert_env_line "$config" 'POWER_MANAGE_WEBHOOK_URL='
    assert_env_line "$config" 'POWER_MANAGE_CA_CERT_FILE=/run/certs/ca.crt'
    assert_env_line "$config" 'POWER_MANAGE_CA_KEY_FILE=/run/certs/ca.key'
    assert_env_line "$config" 'POWER_MANAGE_AGENT_TLS_CERT_FILE=/run/certs/control.crt'
    assert_env_line "$config" 'POWER_MANAGE_AGENT_TLS_KEY_FILE=/run/certs/control.key'
    assert_env_line "$config" 'POWER_MANAGE_PUBLIC_TLS_CERT_FILE=/run/certs/control.crt'
    assert_env_line "$config" 'POWER_MANAGE_PUBLIC_TLS_KEY_FILE=/run/certs/control.key'
    assert_env_line "$config" 'POWER_MANAGE_ENCRYPTION_KEY_FILE=/run/secrets/encryption.key'
    assert_env_line "$config" 'POWER_MANAGE_SESSION_SIGNING_KEY_FILE=/run/secrets/session-signing.pem'
    assert_env_line "$config" 'POWER_MANAGE_SEALING_KEY_FILE=/run/secrets/sealing.key'
    assert_archive_isolated "$config" "$directory"

    if grep -R -iEq 'valkey|asynq|indexer|password_auth|postgres|database_url' "$directory/config"; then
        return 1
    fi
	[[ ! -e "$directory/certs/postgres.crt" ]]
	[[ ! -e "$directory/secrets/postgres.password" ]]
    # Match the verdict text, not the exit status: OpenSSL 3.0 exits 0 even for
    # a name that does NOT match, so an exit-code assertion here would hold on
    # any certificate and prove nothing.
    [[ "$(openssl x509 -in "$directory/certs/control.crt" -checkhost agents.example.test -noout 2>/dev/null)" \
        == "Hostname agents.example.test does match certificate" ]]
    [[ "$(openssl x509 -in "$directory/certs/control.crt" -checkhost control -noout 2>/dev/null)" \
        == "Hostname control does match certificate" ]]

    local before after
    before="$(sha256sum "$directory/certs/ca.key" "$directory/certs/control.key" "$directory/secrets/sealing.key")"
    run_setup "$directory" >/dev/null
    after="$(sha256sum "$directory/certs/ca.key" "$directory/certs/control.key" "$directory/secrets/sealing.key")"
    [[ "$before" == "$after" ]]
}

test_equal_domains_fail() {
    local directory="$1"
    new_fixture "$directory" manage.example.test manage.example.test
    ! run_setup "$directory" >/dev/null 2>&1
}

test_partial_ca_fails() {
    local directory="$1"
    new_fixture "$directory" manage.example.test agents.example.test
    mkdir -p "$directory/certs"
    printf 'not a complete CA\n' > "$directory/certs/ca.crt"
    ! run_setup "$directory" >/dev/null 2>&1
}

test_example_values_fail() {
    local directory="$1"
    new_fixture "$directory" manage.example.com agents.example.com
    ! run_setup "$directory" >/dev/null 2>&1
}

# Removing the fixture's separate storage leaves the deploy tree as it looks
# before an operator provides any: database and archive on one filesystem,
# which is the configuration control refuses to boot.
test_shared_filesystem_archive_fails() {
    local directory="$1" output
    new_fixture "$directory" manage.example.test agents.example.test
    rm -f "$directory/data/backups"

    if output="$(run_setup "$directory" 2>&1)"; then
        printf 'setup.sh rendered a configuration control refuses to start\n' >&2
        return 1
    fi
    # An operator reading only this message has to know which two paths
    # collided, so both are named.
    grep -Fq -- "$directory/data/control" <<<"$output"
    grep -Fq -- "$directory/data/backups" <<<"$output"
    # The point of the check: a configuration that cannot boot never reaches
    # the disk, and no key material is generated for it either.
    [[ ! -e "$directory/config/control.env" ]]
    [[ ! -e "$directory/certs/ca.key" ]]
}

test_backend_name_missing_fails() {
    local directory="$1"
    new_fixture "$directory" manage.example.test agents.example.test
    run_setup "$directory" >/dev/null
    openssl req -new -key "$directory/certs/control.key" \
        -subj '/CN=agents.example.test/O=Power Manage' \
        -out "$directory/certs/control.csr" >/dev/null 2>&1
    openssl x509 -req -in "$directory/certs/control.csr" \
        -CA "$directory/certs/ca.crt" -CAkey "$directory/certs/ca.key" \
        -CAcreateserial -days 825 \
        -extfile <(printf 'subjectAltName=DNS:agents.example.test\nextendedKeyUsage=serverAuth\nkeyUsage=digitalSignature\n') \
        -out "$directory/certs/control.crt" >/dev/null 2>&1
    ! run_setup "$directory" >/dev/null 2>&1
}

# The archive storage every fixture is given lives here, on a filesystem that
# is not the one holding the fixtures themselves.
ARCHIVE_ROOT="$(mktemp -d /dev/shm/pm-setup-test-XXXXXX)"
fixture_one="$(mktemp -d)"
fixture_two="$(mktemp -d)"
fixture_three="$(mktemp -d)"
fixture_four="$(mktemp -d)"
fixture_five="$(mktemp -d)"
fixture_six="$(mktemp -d)"
trap 'rm -rf "$ARCHIVE_ROOT" "$fixture_one" "$fixture_two" "$fixture_three" "$fixture_four" "$fixture_five" "$fixture_six"' EXIT

test_secure_idempotent_setup "$fixture_one"
printf 'PASS secure and idempotent setup\n'
test_equal_domains_fail "$fixture_two"
printf 'PASS equal domains rejected\n'
test_partial_ca_fails "$fixture_three"
printf 'PASS partial CA rejected\n'
test_example_values_fail "$fixture_four"
printf 'PASS example values rejected\n'
test_shared_filesystem_archive_fails "$fixture_five"
printf 'PASS shared-filesystem audit archive rejected\n'
test_backend_name_missing_fails "$fixture_six"
printf 'PASS internal backend name required\n'
