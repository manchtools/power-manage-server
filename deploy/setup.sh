#!/usr/bin/env bash

set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS_DIR="$SCRIPT_DIR/certs"
CONFIG_DIR="$SCRIPT_DIR/config"
SECRETS_DIR="$SCRIPT_DIR/secrets"
DATA_DIR="$SCRIPT_DIR/data"

info() { printf '[INFO] %s\n' "$*"; }
fail() { printf '[ERROR] %s\n' "$*" >&2; exit 1; }

require_command() {
    command -v "$1" >/dev/null 2>&1 || fail "$1 is required"
}

load_environment() {
    [[ -f "$SCRIPT_DIR/.env" ]] || fail "copy .env.example to .env and set the two domains and ACME email"
    set -a
    # This is an operator-owned Compose environment file.
    # shellcheck disable=SC1091
    source "$SCRIPT_DIR/.env"
    set +a
}

validate_environment() {
    local hostname='^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$'
    [[ "${CONTROL_DOMAIN:-}" =~ $hostname ]] || fail "CONTROL_DOMAIN must be a fully-qualified hostname"
    [[ "${AGENT_DOMAIN:-}" =~ $hostname ]] || fail "AGENT_DOMAIN must be a fully-qualified hostname"
    [[ "$CONTROL_DOMAIN" != "$AGENT_DOMAIN" ]] || fail "CONTROL_DOMAIN and AGENT_DOMAIN must differ"
    [[ "${ACME_EMAIL:-}" =~ ^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$ ]] || fail "ACME_EMAIL is invalid"
    [[ "$CONTROL_DOMAIN" != manage.example.com && "$AGENT_DOMAIN" != agents.example.com ]] \
        || fail "replace the example hostnames in .env"
    [[ "$ACME_EMAIL" != admin@example.com ]] || fail "replace the example ACME email in .env"
    [[ "${LOG_LEVEL:-info}" =~ ^(debug|info|warn|error)$ ]] || fail "LOG_LEVEL must be debug, info, warn, or error"
    [[ "${LOG_FORMAT:-json}" =~ ^(json|text)$ ]] || fail "LOG_FORMAT must be json or text"
}

require_pair() {
    local first="$1" second="$2" description="$3"
    if [[ -e "$first" || -e "$second" ]]; then
        [[ -f "$first" && -f "$second" ]] || fail "$description requires both $(basename "$first") and $(basename "$second")"
        return 0
    fi
    return 1
}

validate_key_pair() {
    local certificate="$1" key="$2" description="$3"
    openssl x509 -in "$certificate" -noout >/dev/null
    openssl pkey -in "$key" -noout >/dev/null
    cmp -s \
        <(openssl x509 -in "$certificate" -pubkey -noout | openssl pkey -pubin -outform DER 2>/dev/null) \
        <(openssl pkey -in "$key" -pubout -outform DER 2>/dev/null) \
        || fail "$description certificate and private key do not match"
}

# docref: begin generated-material
ensure_ca() {
    if require_pair "$CERTS_DIR/ca.crt" "$CERTS_DIR/ca.key" "certificate authority"; then
        validate_key_pair "$CERTS_DIR/ca.crt" "$CERTS_DIR/ca.key" "certificate authority"
        openssl verify -CAfile "$CERTS_DIR/ca.crt" "$CERTS_DIR/ca.crt" >/dev/null
        openssl x509 -in "$CERTS_DIR/ca.crt" -text -noout | grep -q 'CA:TRUE' \
            || fail "ca.crt is not a certificate authority"
        info "Using existing certificate authority"
        return
    fi

    info "Generating internal Ed25519 certificate authority"
    openssl genpkey -algorithm Ed25519 -out "$CERTS_DIR/ca.key"
    openssl req -new -x509 -key "$CERTS_DIR/ca.key" -days 3650 \
        -subj "/CN=Power Manage Internal CA/O=Power Manage" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" \
        -out "$CERTS_DIR/ca.crt"
}

ensure_certificate() {
    local name="$1" subject="$2" extensions="$3"
    local certificate="$CERTS_DIR/$name.crt" key="$CERTS_DIR/$name.key" csr="$CERTS_DIR/$name.csr"
    if require_pair "$certificate" "$key" "$name certificate"; then
        validate_key_pair "$certificate" "$key" "$name"
        openssl verify -CAfile "$CERTS_DIR/ca.crt" "$certificate" >/dev/null
        return
    fi

    info "Generating $name certificate"
    openssl genpkey -algorithm Ed25519 -out "$key"
    openssl req -new -key "$key" -subj "$subject" -out "$csr"
    openssl x509 -req -in "$csr" -CA "$CERTS_DIR/ca.crt" -CAkey "$CERTS_DIR/ca.key" \
        -CAcreateserial -days 825 -extfile <(printf '%b\n' "$extensions") -out "$certificate"
    rm -f "$csr"
    openssl verify -CAfile "$CERTS_DIR/ca.crt" "$certificate" >/dev/null
}

ensure_certificates() {
    ensure_certificate control "/CN=$AGENT_DOMAIN/O=Power Manage" \
        "subjectAltName=DNS:$AGENT_DOMAIN,DNS:control,DNS:localhost\nextendedKeyUsage=serverAuth\nkeyUsage=digitalSignature"
    openssl x509 -in "$CERTS_DIR/control.crt" -checkhost "$AGENT_DOMAIN" -noout >/dev/null \
        || fail "control.crt does not cover AGENT_DOMAIN; replace control.crt and control.key"
    openssl x509 -in "$CERTS_DIR/control.crt" -checkhost control -noout >/dev/null \
        || fail "control.crt does not cover the internal control service name; replace control.crt and control.key"

    ensure_certificate postgres "/CN=postgres/O=Power Manage" \
        "subjectAltName=DNS:postgres,DNS:localhost\nextendedKeyUsage=serverAuth\nkeyUsage=digitalSignature"
    openssl x509 -in "$CERTS_DIR/postgres.crt" -checkhost postgres -noout >/dev/null \
        || fail "postgres.crt does not cover the postgres service name"

    ensure_certificate control-datastore "/CN=powermanage/O=Power Manage" \
        "extendedKeyUsage=clientAuth\nkeyUsage=digitalSignature"
}

ensure_secret_files() {
    if [[ ! -f "$SECRETS_DIR/postgres.password" ]]; then
        openssl rand -base64 48 > "$SECRETS_DIR/postgres.password"
    fi
    if [[ ! -f "$SECRETS_DIR/encryption.key" ]]; then
        openssl rand -hex 32 > "$SECRETS_DIR/encryption.key"
    fi
    if [[ ! -f "$SECRETS_DIR/session-signing.pem" ]]; then
        openssl genpkey -algorithm Ed25519 -out "$SECRETS_DIR/session-signing.pem"
    fi
    if [[ ! -f "$SECRETS_DIR/sealing.key" ]]; then
        openssl rand -hex 32 > "$SECRETS_DIR/sealing.key"
    fi

    printf '%s\n' \
        'postgres://powermanage@postgres:5432/powermanage?sslmode=verify-full&sslrootcert=/run/certs/ca.crt&sslcert=/run/certs/control-datastore.crt&sslkey=/run/certs/control-datastore.key' \
        > "$SECRETS_DIR/database.url"

    [[ -s "$SECRETS_DIR/postgres.password" && "$(wc -c < "$SECRETS_DIR/postgres.password")" -le 256 ]] \
        || fail "postgres.password must be non-empty and no larger than 256 bytes"
    grep -Eq '^[0-9a-fA-F]{64}$' "$SECRETS_DIR/encryption.key" \
        || fail "encryption.key must contain exactly 32 hex-encoded bytes"
    grep -Eq '^[0-9a-fA-F]{64}$' "$SECRETS_DIR/sealing.key" \
        || fail "sealing.key must contain exactly 32 hex-encoded bytes"
    openssl pkey -in "$SECRETS_DIR/session-signing.pem" -text -noout 2>/dev/null | grep -q ED25519 \
        || fail "session-signing.pem must contain an Ed25519 private key"
}

write_config() {
    cat > "$CONFIG_DIR/control.json" <<EOF
{
  "public_listen": "0.0.0.0:8081",
  "agent_listen": "172.30.0.3:8082",
  "public_base_url": "https://${CONTROL_DOMAIN}",
  "agent_url": "https://${AGENT_DOMAIN}",
  "terminal_url": "wss://${CONTROL_DOMAIN}/terminal",
  "cors_origins": ["https://${CONTROL_DOMAIN}"],
  "terminal_origins": ["${CONTROL_DOMAIN}"],
  "trusted_proxies": ["172.29.0.2"],
  "agent_proxy_sources": ["172.30.0.2"],
  "log_level": "${LOG_LEVEL:-info}",
  "log_format": "${LOG_FORMAT:-json}",
  "certificate_validity": "8760h",
  "heartbeat_interval": "30s",
	"audit_retention": "2160h",
  "artifact_path": "/var/lib/power-manage/artifacts",
  "backup_path": "/var/lib/power-manage/backups",
  "ca_cert_file": "/run/certs/ca.crt",
  "ca_key_file": "/run/certs/ca.key",
  "agent_tls_cert_file": "/run/certs/control.crt",
  "agent_tls_key_file": "/run/certs/control.key",
  "public_tls_cert_file": "/run/certs/control.crt",
  "public_tls_key_file": "/run/certs/control.key",
  "database_url_file": "/run/secrets/database.url",
  "encryption_key_file": "/run/secrets/encryption.key",
  "session_signing_key_file": "/run/secrets/session-signing.pem",
  "sealing_key_file": "/run/secrets/sealing.key"
}
EOF
}

validate_permissions() {
    local private
    for private in "$CERTS_DIR/ca.key" "$CERTS_DIR/control.key" "$CERTS_DIR/postgres.key" \
        "$CERTS_DIR/control-datastore.key" "$SECRETS_DIR"/*; do
        [[ "$(stat -c '%a' "$private")" =~ ^[0-6]00$ ]] \
            || fail "$private must not be group/world accessible"
    done
    [[ -w "$DATA_DIR/artifacts" && -w "$DATA_DIR/backups" ]] \
        || fail "artifact and backup paths must be writable"
}

main() {
    require_command openssl
    require_command cmp
    require_command stat
    load_environment
    validate_environment

    mkdir -p "$CERTS_DIR" "$CONFIG_DIR" "$SECRETS_DIR" \
        "$DATA_DIR/postgres" "$DATA_DIR/traefik" "$DATA_DIR/artifacts" "$DATA_DIR/backups"
    chmod 700 "$CERTS_DIR" "$CONFIG_DIR" "$SECRETS_DIR"
    # PostgreSQL's entrypoint drops to its service UID after preparing PGDATA;
    # it must be able to traverse the bind-mount root on the second pass.
    chmod 755 "$DATA_DIR/postgres"
    chmod 600 "$SCRIPT_DIR/.env"
    touch "$DATA_DIR/traefik/acme.json"
    chmod 600 "$DATA_DIR/traefik/acme.json"

    ensure_ca
    ensure_certificates
    ensure_secret_files
    write_config

    chmod 600 "$CERTS_DIR"/*.key "$SECRETS_DIR"/* "$CONFIG_DIR/control.json"
    chmod 644 "$CERTS_DIR"/*.crt
    validate_permissions

    info "Deployment material is ready"
    printf '%s\n' \
        "Start:     cd $SCRIPT_DIR && docker compose up -d --wait" \
        "Bootstrap: cd $SCRIPT_DIR && docker compose exec control control bootstrap-admin"
}
# docref: end generated-material

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
