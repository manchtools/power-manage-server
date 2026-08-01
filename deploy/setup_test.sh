#!/usr/bin/env bash

set -euo pipefail

DEPLOY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

new_fixture() {
    local directory="$1" control_domain="$2" agent_domain="$3"
    mkdir -p "$directory"
    cat > "$directory/.env" <<EOF
CONTROL_DOMAIN=$control_domain
AGENT_DOMAIN=$agent_domain
ACME_EMAIL=admin@example.test
LOG_LEVEL=info
LOG_FORMAT=json
EOF
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
    grep -q '"agent_listen": "172.30.0.3:8082"' "$directory/config/control.json"
    grep -q '"agent_proxy_sources": \["172.30.0.2"\]' "$directory/config/control.json"
    if grep -R -iEq 'valkey|asynq|indexer|password_auth' "$directory/config"; then
        return 1
    fi
    python3 -m json.tool "$directory/config/control.json" >/dev/null
    openssl x509 -in "$directory/certs/control.crt" -checkhost agents.example.test -noout >/dev/null

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

fixture_one="$(mktemp -d)"
fixture_two="$(mktemp -d)"
fixture_three="$(mktemp -d)"
fixture_four="$(mktemp -d)"
trap 'rm -rf "$fixture_one" "$fixture_two" "$fixture_three" "$fixture_four"' EXIT

test_secure_idempotent_setup "$fixture_one"
printf 'PASS secure and idempotent setup\n'
test_equal_domains_fail "$fixture_two"
printf 'PASS equal domains rejected\n'
test_partial_ca_fails "$fixture_three"
printf 'PASS partial CA rejected\n'
test_example_values_fail "$fixture_four"
printf 'PASS example values rejected\n'
