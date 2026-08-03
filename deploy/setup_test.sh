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

new_fixture() {
    local directory="$1" control_domain="$2" agent_domain="$3"
    mkdir -p "$directory"
    cat > "$directory/.env" <<EOF
CONTROL_DOMAIN=$control_domain
AGENT_DOMAIN=$agent_domain
ACME_EMAIL=admin@example.test
EOF
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

fixture_one="$(mktemp -d)"
fixture_two="$(mktemp -d)"
fixture_three="$(mktemp -d)"
fixture_four="$(mktemp -d)"
fixture_five="$(mktemp -d)"
trap 'rm -rf "$fixture_one" "$fixture_two" "$fixture_three" "$fixture_four" "$fixture_five"' EXIT

test_secure_idempotent_setup "$fixture_one"
printf 'PASS secure and idempotent setup\n'
test_equal_domains_fail "$fixture_two"
printf 'PASS equal domains rejected\n'
test_partial_ca_fails "$fixture_three"
printf 'PASS partial CA rejected\n'
test_example_values_fail "$fixture_four"
printf 'PASS example values rejected\n'
test_backend_name_missing_fails "$fixture_five"
printf 'PASS internal backend name required\n'
