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
    POWER_MANAGE_CA_TRUST_BUNDLE_FILE
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

# The operator authors config/traefik-dns.env by hand, so the fixture writes it
# with an explicit mode. setup.sh must judge its presence, its emptiness, and
# its permissions without ever reading a value out of it.
write_dns_credentials() {
    local directory="$1" mode="$2" contents="${3-}"
    mkdir -p "$directory/config"
    printf '%s' "$contents" > "$directory/config/traefik-dns.env"
    chmod "$mode" "$directory/config/traefik-dns.env"
}

# The ACME-challenge cases need a fixture each, and most also need .env lines
# new_fixture does not write, so they allocate under one root the trap already
# removes instead of extending the named list of fixtures.
challenge_fixture() {
    local directory
    directory="$(mktemp -d "$CHALLENGE_ROOT/XXXXXX")"
    new_fixture "$directory" manage.example.test agents.example.test
    printf '%s\n' "$directory"
}

# The .env parser cases append to the file new_fixture wrote, and likewise need
# one fixture each.
env_fixture() {
    local directory
    directory="$(mktemp -d "$ENV_ROOT/XXXXXX")"
    new_fixture "$directory" manage.example.test agents.example.test
    printf '%s\n' "$directory"
}

# A configuration setup.sh cannot use must be refused before it generates
# anything. An operator who corrects the variable and re-runs must not already
# own a CA, a control certificate, or secrets produced by the rejected attempt.
assert_setup_refused() {
    local directory="$1" expected="$2" output artifact
    if output="$(run_setup "$directory" 2>&1)"; then
        printf 'setup.sh accepted an unusable ACME challenge configuration\n' >&2
        return 1
    fi
    grep -Fq -- "$expected" <<<"$output" || {
        printf 'refusal does not name the problem (%s): %s\n' "$expected" "$output" >&2
        return 1
    }
    for artifact in certs/ca.key certs/ca.crt certs/control.key certs/control.crt \
        secrets/encryption.key secrets/sealing.key secrets/session-signing.pem \
        config/control.env config/traefik-acme.env; do
        [[ ! -e "$directory/$artifact" ]] || {
            printf 'refused run left %s behind\n' "$directory/$artifact" >&2
            return 1
        }
    done
}

# Compose merges every env_file into the service environment, so the resolved
# configuration is where the wiring can be asserted: a rendered file nothing
# references would satisfy a file-content check and reach Traefik never.
compose_service_environment() {
    local directory="$1"
    docker compose -p pm-challenge-test -f "$directory/compose.yml" config --format json \
        | python3 -c 'import json, sys
service = json.load(sys.stdin)["services"]["traefik"]["environment"]
print("\n".join(f"{name}={value}" for name, value in service.items()))'
}

# `docker compose up -d --wait` waits on the services that declare a
# healthcheck and on no others, so a service without one is reported ready the
# moment it is started. Traefik is the only way into the deployment; without
# its healthcheck the wait returns while every request still fails.
assert_service_healthcheck() {
    local directory="$1" service="$2" expected="$3" command_line
    command_line="$(docker compose -p pm-challenge-test -f "$directory/compose.yml" config --format json \
        | python3 -c 'import json, sys
service = json.load(sys.stdin)["services"][sys.argv[1]]
print(" ".join(service.get("healthcheck", {}).get("test", [])))' "$service")"
    [[ "$command_line" == *"$expected"* ]] || {
        printf '%s healthcheck is "%s", want one running %s\n' "$service" "$command_line" "$expected" >&2
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
    assert_env_line "$config" 'POWER_MANAGE_CA_TRUST_BUNDLE_FILE=/run/certs/ca-trust-bundle.crt'
    assert_env_line "$config" 'POWER_MANAGE_AGENT_TLS_CERT_FILE=/run/certs/control.crt'
    assert_env_line "$config" 'POWER_MANAGE_AGENT_TLS_KEY_FILE=/run/certs/control.key'
    assert_env_line "$config" 'POWER_MANAGE_PUBLIC_TLS_CERT_FILE=/run/certs/control.crt'
    assert_env_line "$config" 'POWER_MANAGE_PUBLIC_TLS_KEY_FILE=/run/certs/control.key'
    assert_env_line "$config" 'POWER_MANAGE_ENCRYPTION_KEY_FILE=/run/secrets/encryption.key'
    assert_env_line "$config" 'POWER_MANAGE_SESSION_SIGNING_KEY_FILE=/run/secrets/session-signing.pem'
    assert_env_line "$config" 'POWER_MANAGE_SEALING_KEY_FILE=/run/secrets/sealing.key'
    cmp -s "$directory/certs/ca.crt" "$directory/certs/ca-trust-bundle.crt"
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

test_ca_rotation_preserves_old_and_active_trust() {
    local directory="$1"
    new_fixture "$directory" manage.example.test agents.example.test
    run_setup "$directory" >/dev/null
    cp "$directory/certs/ca.crt" "$directory/old-ca.crt"
    rm -f "$directory/certs/ca.crt" "$directory/certs/ca.key" \
        "$directory/certs/control.crt" "$directory/certs/control.key"

    run_setup "$directory" >/dev/null

    openssl verify -CAfile "$directory/certs/ca-trust-bundle.crt" \
        "$directory/old-ca.crt" >/dev/null
    openssl verify -CAfile "$directory/certs/ca-trust-bundle.crt" \
        "$directory/certs/ca.crt" >/dev/null
}

# .env is an operator-authored data file that Compose reads as KEY=VALUE lines
# and never executes, so setup.sh must not execute it either. A value that
# looks like a command substitution has to arrive as those literal characters;
# sourcing the file would instead run it as whoever ran setup.sh.
test_env_file_values_are_never_executed() {
    local directory
    directory="$(env_fixture)"
    printf 'EVIL=$(touch %s/pwned)\n' "$directory" >> "$directory/.env"

    # The line is a well-formed assignment, so the run proceeds and only the
    # value is left uninterpreted. Asserting the run completed matters: without
    # it, "no pwned file" would also hold for a setup.sh that died first.
    run_setup "$directory" >/dev/null
    [[ -f "$directory/config/control.env" ]] || {
        printf 'setup.sh did not complete, so the value was never parsed\n' >&2
        return 1
    }
    [[ ! -e "$directory/pwned" ]] || {
        printf 'setup.sh executed a value out of .env\n' >&2
        return 1
    }
}

# A line that is not an assignment is a line whose meaning setup.sh and Compose
# would each have to guess at. It is refused, and the message names where it is
# so the operator does not go looking.
test_env_file_rejects_a_non_assignment_line() {
    local directory
    directory="$(env_fixture)"
    printf 'this is not an assignment\n' >> "$directory/.env"
    assert_setup_refused "$directory" 'line 4 is not a KEY=VALUE assignment'
}

# Compose strips a surrounding quote pair and bash keeps whatever the quoting
# rules produce, so a quoted value means two different things in one
# deployment. Quote-free values only.
test_env_file_rejects_a_quoted_value() {
    local directory
    directory="$(env_fixture)"
    printf 'CONTROL_DOMAIN="quoted.example.test"\n' >> "$directory/.env"
    assert_setup_refused "$directory" 'quotes its value'
}

# The challenge type is chosen per deployment and comes from the environment. A
# challenge left in the static file would win for every deployment including
# the dns01 ones, and the DNS provider would never be asked.
test_static_traefik_config_names_no_challenge() {
    if grep -Eq 'httpChallenge|dnsChallenge' "$DEPLOY_DIR/traefik/traefik.yml"; then
        printf 'traefik.yml still pins an ACME challenge type\n' >&2
        return 1
    fi
    grep -Fq 'storage: /letsencrypt/acme.json' "$DEPLOY_DIR/traefik/traefik.yml"
    # `traefik healthcheck --ping`, the container healthcheck compose.yml
    # declares, asks Traefik's own ping endpoint and fails closed when the
    # endpoint is not enabled here.
    grep -Fq 'ping:' "$DEPLOY_DIR/traefik/traefik.yml" || {
        printf 'traefik.yml does not enable ping, so its healthcheck can never succeed\n' >&2
        return 1
    }
}

test_default_challenge_renders_http01() {
    local directory acme credentials
    directory="$(challenge_fixture)"
    run_setup "$directory" >/dev/null

    acme="$directory/config/traefik-acme.env"
    credentials="$directory/config/traefik-dns.env"
    [[ "$(stat -c '%a' "$acme")" == 600 ]]
    assert_env_line "$acme" 'TRAEFIK_CERTIFICATESRESOLVERS_LETSENCRYPT_ACME_HTTPCHALLENGE_ENTRYPOINT=web'
    # Exactly one setting: an http01 deployment must not also carry a
    # half-configured DNS challenge Traefik would try alongside it.
    [[ "$(wc -l < "$acme")" == 1 ]]
    # compose.yml references the credentials file unconditionally and Compose
    # refuses to read a configuration whose env_file is missing, so http01 gets
    # an empty one rather than no file at all.
    [[ -f "$credentials" && ! -s "$credentials" ]]
    [[ "$(stat -c '%a' "$credentials")" == 600 ]]
}

test_dns01_renders_provider_and_public_resolvers() {
    local directory acme
    directory="$(challenge_fixture)"
    printf 'ACME_CHALLENGE=dns01\nACME_DNS_PROVIDER=hetzner\n' >> "$directory/.env"
    write_dns_credentials "$directory" 600 $'HETZNER_API_KEY=example-token\n'
    run_setup "$directory" >/dev/null

    acme="$directory/config/traefik-acme.env"
    assert_env_line "$acme" 'TRAEFIK_CERTIFICATESRESOLVERS_LETSENCRYPT_ACME_DNSCHALLENGE_PROVIDER=hetzner'
    # Pinned public resolvers: a homelab's split-horizon DNS answers the
    # propagation check from the internal view, where the challenge record does
    # not exist, and the order then never completes.
    assert_env_line "$acme" 'TRAEFIK_CERTIFICATESRESOLVERS_LETSENCRYPT_ACME_DNSCHALLENGE_RESOLVERS=1.1.1.1:53,9.9.9.9:53'
    [[ "$(wc -l < "$acme")" == 2 ]]
    [[ "$(stat -c '%a' "$acme")" == 600 ]]
    if grep -q HTTPCHALLENGE "$acme"; then
        printf 'dns01 rendered the http01 entrypoint as well\n' >&2
        return 1
    fi
    # The operator's file is consulted for its existence, size, and mode only,
    # and is handed to Traefik exactly as written.
    [[ "$(cat "$directory/config/traefik-dns.env")" == 'HETZNER_API_KEY=example-token' ]]
}

test_dns01_without_provider_fails() {
    local directory
    directory="$(challenge_fixture)"
    printf 'ACME_CHALLENGE=dns01\n' >> "$directory/.env"
    write_dns_credentials "$directory" 600 $'HETZNER_API_KEY=example-token\n'
    assert_setup_refused "$directory" 'ACME_DNS_PROVIDER is required'
}

test_dns01_without_credentials_fails() {
    local directory
    directory="$(challenge_fixture)"
    printf 'ACME_CHALLENGE=dns01\nACME_DNS_PROVIDER=hetzner\n' >> "$directory/.env"
    # No credentials file at all. The empty one setup.sh creates for http01
    # must never stand in for provider credentials, or the deployment would
    # start and fail its first certificate order instead of failing here.
    assert_setup_refused "$directory" 'traefik-dns.env does not exist'
}

test_dns01_with_empty_credentials_fails() {
    local directory
    directory="$(challenge_fixture)"
    printf 'ACME_CHALLENGE=dns01\nACME_DNS_PROVIDER=hetzner\n' >> "$directory/.env"
    write_dns_credentials "$directory" 600 ''
    assert_setup_refused "$directory" 'traefik-dns.env is empty'
}

test_dns01_with_readable_credentials_fails() {
    local directory
    directory="$(challenge_fixture)"
    printf 'ACME_CHALLENGE=dns01\nACME_DNS_PROVIDER=hetzner\n' >> "$directory/.env"
    write_dns_credentials "$directory" 644 $'HETZNER_API_KEY=example-token\n'
    # Refused, not repaired: a provider credential every local account could
    # read is one the operator has to rotate, not one a silent chmod fixes.
    assert_setup_refused "$directory" 'traefik-dns.env must not be group/world accessible'
}

test_unknown_challenge_fails() {
    local directory
    directory="$(challenge_fixture)"
    printf 'ACME_CHALLENGE=bogus\n' >> "$directory/.env"
    assert_setup_refused "$directory" 'ACME_CHALLENGE must be http01 or dns01'
}

# Nothing setup.sh prints or renders may carry a provider credential; only the
# operator's own file holds one.
test_provider_credentials_never_leave_their_file() {
    local directory output leaked
    directory="$(challenge_fixture)"
    printf 'ACME_CHALLENGE=dns01\nACME_DNS_PROVIDER=hetzner\n' >> "$directory/.env"
    write_dns_credentials "$directory" 600 $'HETZNER_API_KEY=CANARY_SECRET_VALUE_9X7\n'

    output="$(run_setup "$directory" 2>&1)"
    # The run has to have taken the real dns01 path, or the canary below proves
    # only that a credential nothing read was not printed.
    assert_env_line "$directory/config/traefik-acme.env" \
        'TRAEFIK_CERTIFICATESRESOLVERS_LETSENCRYPT_ACME_DNSCHALLENGE_PROVIDER=hetzner'
    if grep -Fq CANARY_SECRET_VALUE_9X7 <<<"$output"; then
        printf 'setup.sh printed the provider credential\n' >&2
        return 1
    fi
    leaked="$(grep -rlF CANARY_SECRET_VALUE_9X7 "$directory" \
        | grep -vFx "$directory/config/traefik-dns.env" || true)"
    [[ -z "$leaked" ]] || {
        printf 'provider credential copied into: %s\n' "$leaked" >&2
        return 1
    }
}

# This one reports its own verdict, because a skipped compose validation must
# not be printed as a pass.
test_compose_configuration_valid_in_both_modes() {
    local directory
    if ! docker compose version >/dev/null 2>&1; then
        printf 'SKIP compose configuration: the Docker Compose plugin is unavailable\n'
        return 0
    fi

    directory="$(challenge_fixture)"
    cp "$DEPLOY_DIR/compose.yml" "$directory/compose.yml"
    run_setup "$directory" >/dev/null
    docker compose -p pm-challenge-test -f "$directory/compose.yml" config --quiet
    compose_service_environment "$directory" > "$directory/resolved.env"
    assert_env_line "$directory/resolved.env" \
        'TRAEFIK_CERTIFICATESRESOLVERS_LETSENCRYPT_ACME_HTTPCHALLENGE_ENTRYPOINT=web'
    assert_service_healthcheck "$directory" traefik 'traefik healthcheck'

    directory="$(challenge_fixture)"
    cp "$DEPLOY_DIR/compose.yml" "$directory/compose.yml"
    printf 'ACME_CHALLENGE=dns01\nACME_DNS_PROVIDER=hetzner\n' >> "$directory/.env"
    write_dns_credentials "$directory" 600 $'HETZNER_API_KEY=example-token\n'
    run_setup "$directory" >/dev/null
    docker compose -p pm-challenge-test -f "$directory/compose.yml" config --quiet
    compose_service_environment "$directory" > "$directory/resolved.env"
    assert_env_line "$directory/resolved.env" \
        'TRAEFIK_CERTIFICATESRESOLVERS_LETSENCRYPT_ACME_DNSCHALLENGE_PROVIDER=hetzner'
    assert_env_line "$directory/resolved.env" \
        'TRAEFIK_CERTIFICATESRESOLVERS_LETSENCRYPT_ACME_DNSCHALLENGE_RESOLVERS=1.1.1.1:53,9.9.9.9:53'
    # The credentials are Traefik's to read, not setup.sh's: Compose carries
    # them from the operator's file into the container.
    assert_env_line "$directory/resolved.env" 'HETZNER_API_KEY=example-token'
    printf 'PASS compose configuration valid in both challenge modes\n'
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
fixture_seven="$(mktemp -d)"
CHALLENGE_ROOT="$(mktemp -d)"
ENV_ROOT="$(mktemp -d)"
trap 'rm -rf "$ARCHIVE_ROOT" "$fixture_one" "$fixture_two" "$fixture_three" "$fixture_four" "$fixture_five" "$fixture_six" "$fixture_seven" "$CHALLENGE_ROOT" "$ENV_ROOT"' EXIT

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
test_ca_rotation_preserves_old_and_active_trust "$fixture_seven"
printf 'PASS CA rotation trust bundle preserved\n'
test_env_file_values_are_never_executed
printf 'PASS .env values are never executed\n'
test_env_file_rejects_a_non_assignment_line
printf 'PASS .env line that is not an assignment rejected\n'
test_env_file_rejects_a_quoted_value
printf 'PASS .env quoted value rejected\n'
test_static_traefik_config_names_no_challenge
printf 'PASS static Traefik configuration pins no challenge type and enables ping\n'
test_default_challenge_renders_http01
printf 'PASS default ACME challenge renders http01\n'
test_dns01_renders_provider_and_public_resolvers
printf 'PASS dns01 renders the provider and public resolvers\n'
test_dns01_without_provider_fails
printf 'PASS dns01 without a provider rejected\n'
test_dns01_without_credentials_fails
printf 'PASS dns01 without a credentials file rejected\n'
test_dns01_with_empty_credentials_fails
printf 'PASS dns01 with empty credentials rejected\n'
test_dns01_with_readable_credentials_fails
printf 'PASS dns01 with group/world readable credentials rejected\n'
test_unknown_challenge_fails
printf 'PASS unknown ACME challenge rejected\n'
test_provider_credentials_never_leave_their_file
printf 'PASS provider credentials stay in their file\n'
test_compose_configuration_valid_in_both_modes
