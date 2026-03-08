#!/bin/bash
#
# Power Manage Server - Setup Script
#
# This script:
# 1. Validates the .env configuration
# 2. Generates internal PKI certificates (CA, gateway, control) using Go's crypto/x509
# 3. Prepares data directories for PostgreSQL and Traefik
#
# Usage: ./setup.sh

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS_DIR="$SCRIPT_DIR/certs"
DATA_DIR="$SCRIPT_DIR/data"

check_env() {
    if [[ ! -f "$SCRIPT_DIR/.env" ]]; then
        log_error ".env file not found!"
        log_info "Copy .env.example to .env and configure it:"
        log_info "  cp .env.example .env"
        log_info "  \$EDITOR .env"
        exit 1
    fi

    set -a
    source "$SCRIPT_DIR/.env"
    set +a

    local missing=0

    if [[ -z "$POSTGRES_PASSWORD" ]] || [[ "$POSTGRES_PASSWORD" == "CHANGE_ME"* ]]; then
        log_error "POSTGRES_PASSWORD must be set in .env"
        missing=1
    fi

    if [[ -z "$INDEXER_POSTGRES_PASSWORD" ]] || [[ "$INDEXER_POSTGRES_PASSWORD" == "CHANGE_ME"* ]]; then
        log_error "INDEXER_POSTGRES_PASSWORD must be set in .env"
        missing=1
    fi

    if [[ -z "$VALKEY_PASSWORD" ]] || [[ "$VALKEY_PASSWORD" == "CHANGE_ME"* ]]; then
        log_error "VALKEY_PASSWORD must be set in .env"
        missing=1
    fi

    if [[ -z "$JWT_SECRET" ]] || [[ "$JWT_SECRET" == "CHANGE_ME"* ]]; then
        log_error "JWT_SECRET must be set in .env"
        missing=1
    fi

    if [[ ${#JWT_SECRET} -lt 32 ]]; then
        log_error "JWT_SECRET must be at least 32 characters"
        missing=1
    fi

    if [[ -z "$ADMIN_EMAIL" ]]; then
        log_error "ADMIN_EMAIL must be set in .env"
        missing=1
    fi

    if [[ -z "$ADMIN_PASSWORD" ]] || [[ "$ADMIN_PASSWORD" == "CHANGE_ME"* ]]; then
        log_error "ADMIN_PASSWORD must be set in .env"
        missing=1
    fi

    if [[ -z "$CONTROL_DOMAIN" ]] || [[ "$CONTROL_DOMAIN" == *"example.com" ]]; then
        log_error "CONTROL_DOMAIN must be set to your actual domain in .env"
        missing=1
    fi

    if [[ -z "$GATEWAY_DOMAIN" ]] || [[ "$GATEWAY_DOMAIN" == *"example.com" ]]; then
        log_error "GATEWAY_DOMAIN must be set to your actual domain in .env"
        missing=1
    fi

    if [[ -z "$ACME_EMAIL" ]] || [[ "$ACME_EMAIL" == "admin@example.com" ]]; then
        log_error "ACME_EMAIL must be set to a valid email for Let's Encrypt in .env"
        missing=1
    fi

    if [[ $missing -eq 1 ]]; then
        exit 1
    fi

    log_info "Environment configuration validated"
}

generate_certs() {
    if [[ -f "$CERTS_DIR/ca.crt" ]] && [[ -f "$CERTS_DIR/ca.key" ]]; then
        log_warn "Certificates already exist in $CERTS_DIR"
        read -p "Regenerate all certificates? This will invalidate all existing agent registrations! [y/N] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_info "Keeping existing certificates"
            return
        fi
        rm -f "$CERTS_DIR/ca.crt" "$CERTS_DIR/ca.key" \
              "$CERTS_DIR/gateway.crt" "$CERTS_DIR/gateway.key" \
              "$CERTS_DIR/control.crt" "$CERTS_DIR/control.key" \
              "$CERTS_DIR/ca.srl"
    fi

    # certgen is bundled alongside setup.sh in the deploy directory.
    # It uses Go's crypto/x509 to generate certificates, ensuring encoding
    # compatibility with Go's TLS verification (no openssl DER mismatches).
    local certgen="$SCRIPT_DIR/certgen"
    if [[ ! -x "$certgen" ]]; then
        log_error "certgen binary not found at $certgen"
        log_info "Build it with: go build -o deploy/certgen ./cmd/certgen"
        exit 1
    fi

    log_info "Generating certificates for ${GATEWAY_DOMAIN}..."
    "$certgen" -dir "$CERTS_DIR" -gateway-domain "${GATEWAY_DOMAIN}"

    chmod 600 "$CERTS_DIR/ca.key" "$CERTS_DIR/gateway.key" "$CERTS_DIR/control.key"
    chmod 644 "$CERTS_DIR/ca.crt" "$CERTS_DIR/gateway.crt" "$CERTS_DIR/control.crt"

    log_info "Certificates generated successfully"
}

show_instructions() {
    echo ""
    echo "=========================================="
    echo "  Power Manage Setup Complete"
    echo "=========================================="
    echo ""
    echo "Next steps:"
    echo ""
    echo "1. Ensure DNS records point to this server:"
    echo "   - ${CONTROL_DOMAIN}"
    echo "   - ${GATEWAY_DOMAIN}"
    echo ""
    echo "2. Start the services:"
    echo "   docker compose up -d"
    echo ""
    echo "   Traefik obtains a Let's Encrypt certificate for the control domain."
    echo "   The gateway uses its internal CA-signed certificate for agent mTLS."
    echo ""
    echo "3. Access the web UI at https://${CONTROL_DOMAIN}"
    echo "   Login with: ${ADMIN_EMAIL}"
    echo ""
    echo "4. If upgrading an existing deployment, set the indexer DB password:"
    echo "   docker exec -it pm-postgres psql -U powermanage -d powermanage \\"
    echo "     -c \"ALTER ROLE pm_indexer PASSWORD '\$INDEXER_POSTGRES_PASSWORD'\""
    echo ""
    echo "5. Create a registration token, then install agents:"
    echo "   curl -fsSL https://github.com/MANCHTOOLS/power-manage-agent/releases/latest/download/install.sh | sudo bash -s -- -s https://${CONTROL_DOMAIN} -t <TOKEN>"
    echo ""
}

main() {
    log_info "Power Manage Server Setup"
    echo ""

    check_env
    generate_certs

    mkdir -p "$DATA_DIR/postgres" "$DATA_DIR/valkey" "$DATA_DIR/traefik"
    log_info "Created data directories: $DATA_DIR/{postgres,valkey,traefik}"

    show_instructions
}

main "$@"
