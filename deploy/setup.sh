#!/bin/bash
#
# Power Manage Server - Setup Script
#
# This script:
# 1. Validates the .env configuration
# 2. Generates the internal CA for agent certificate signing
# 3. Generates the gateway server certificate (signed by the CA)
# 4. Generates the control server certificate for internal mTLS (signed by the CA)
# 5. Generates the control public TLS certificate (signed by the CA, for web UI / API)
# 6. Prepares data directories for PostgreSQL and Traefik
#
# Usage: ./setup.sh

set -e

# Refuse to create files readable by group/other. Private keys are
# chmod'd to 600 explicitly after generation, but a wider default
# umask would still let openssl briefly create the key with 644
# permissions on disk — a window where a racing reader on a
# multi-user host could grab it before the chmod fires. umask 077
# closes that window across every write in this script.
umask 077

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

generate_ca() {
    if [[ -f "$CERTS_DIR/ca.crt" ]] && [[ -f "$CERTS_DIR/ca.key" ]]; then
        log_warn "CA already exists in $CERTS_DIR"
        read -p "Regenerate CA? This will invalidate all existing agent registrations! [y/N] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_info "Keeping existing CA"
            return
        fi
    fi

    log_info "Generating internal Certificate Authority..."
    mkdir -p "$CERTS_DIR"

    log_info "Generating CA private key..."
    openssl genrsa -out "$CERTS_DIR/ca.key" 4096

    log_info "Generating CA certificate..."
    openssl req -new -x509 -days 3650 -key "$CERTS_DIR/ca.key" -out "$CERTS_DIR/ca.crt" \
        -subj "/CN=Power Manage Internal CA/O=Power Manage" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" \
        -addext "subjectKeyIdentifier=hash"

    chmod 600 "$CERTS_DIR/ca.key"
    chmod 644 "$CERTS_DIR/ca.crt"

    log_info "CA generated successfully"
}

generate_gateway_cert() {
    if [[ -f "$CERTS_DIR/gateway.crt" ]] && [[ -f "$CERTS_DIR/gateway.key" ]]; then
        log_warn "Gateway certificate already exists"
        read -p "Regenerate gateway certificate? [y/N] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_info "Keeping existing gateway certificate"
            return
        fi
    fi

    log_info "Generating gateway server certificate for ${GATEWAY_DOMAIN}..."

    # Generate private key
    openssl ecparam -genkey -name prime256v1 -noout -out "$CERTS_DIR/gateway.key"

    # Generate CSR
    openssl req -new -key "$CERTS_DIR/gateway.key" \
        -subj "/CN=${GATEWAY_DOMAIN}/O=Power Manage" \
        -out "$CERTS_DIR/gateway.csr"

    # Sign with CA (extfile sets SAN + AKI for reliable Go x509 chain
    # matching, plus a spiffe:// URI SAN that identifies this cert as
    # a "gateway" peer class — the control server's peer-class
    # middleware requires that class on the InternalService listener
    # so a leaked agent cert cannot impersonate a gateway).
    openssl x509 -req -in "$CERTS_DIR/gateway.csr" \
        -CA "$CERTS_DIR/ca.crt" -CAkey "$CERTS_DIR/ca.key" -CAcreateserial \
        -days 825 \
        -extfile <(printf "subjectAltName=DNS:%s,URI:spiffe://power-manage/gateway\nauthorityKeyIdentifier=keyid:always" "${GATEWAY_DOMAIN}") \
        -out "$CERTS_DIR/gateway.crt"

    rm -f "$CERTS_DIR/gateway.csr"
    chmod 600 "$CERTS_DIR/gateway.key"
    chmod 644 "$CERTS_DIR/gateway.crt"

    log_info "Gateway certificate generated (valid 825 days)"
}

generate_control_cert() {
    if [[ -f "$CERTS_DIR/control.crt" ]] && [[ -f "$CERTS_DIR/control.key" ]]; then
        log_warn "Control certificate already exists"
        read -p "Regenerate control certificate? [y/N] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_info "Keeping existing control certificate"
            return
        fi
    fi

    log_info "Generating control server certificate..."

    # Generate private key
    openssl ecparam -genkey -name prime256v1 -noout -out "$CERTS_DIR/control.key"

    # Generate CSR
    openssl req -new -key "$CERTS_DIR/control.key" \
        -subj "/CN=control/O=Power Manage" \
        -out "$CERTS_DIR/control.csr"

    # Sign with CA (extfile sets SAN + AKI for reliable Go x509 chain
    # matching, plus a spiffe:// URI SAN marking this cert as the
    # "control" peer class — the gateway's GatewayService listener
    # requires that class so an agent cert cannot pose as the control
    # plane and issue admin fan-out calls).
    openssl x509 -req -in "$CERTS_DIR/control.csr" \
        -CA "$CERTS_DIR/ca.crt" -CAkey "$CERTS_DIR/ca.key" -CAcreateserial \
        -days 825 \
        -extfile <(printf "subjectAltName=DNS:control,DNS:localhost,URI:spiffe://power-manage/control\nauthorityKeyIdentifier=keyid:always") \
        -out "$CERTS_DIR/control.crt"

    rm -f "$CERTS_DIR/control.csr"
    chmod 600 "$CERTS_DIR/control.key"
    chmod 644 "$CERTS_DIR/control.crt"

    log_info "Control certificate generated (valid 825 days)"
}

generate_control_public_cert() {
    if [[ -f "$CERTS_DIR/control-public.crt" ]] && [[ -f "$CERTS_DIR/control-public.key" ]]; then
        log_warn "Control public certificate already exists"
        read -p "Regenerate control public certificate? [y/N] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_info "Keeping existing control public certificate"
            return
        fi
    fi

    log_info "Generating control public TLS certificate for ${CONTROL_DOMAIN}..."

    # Generate private key
    openssl ecparam -genkey -name prime256v1 -noout -out "$CERTS_DIR/control-public.key"

    # Generate CSR
    openssl req -new -key "$CERTS_DIR/control-public.key" \
        -subj "/CN=${CONTROL_DOMAIN}/O=Power Manage" \
        -out "$CERTS_DIR/control-public.csr"

    # Sign with CA (extfile sets SAN + AKI for reliable Go x509 chain matching)
    openssl x509 -req -in "$CERTS_DIR/control-public.csr" \
        -CA "$CERTS_DIR/ca.crt" -CAkey "$CERTS_DIR/ca.key" -CAcreateserial \
        -days 825 \
        -extfile <(printf "subjectAltName=DNS:%s,DNS:localhost\nauthorityKeyIdentifier=keyid:always" "${CONTROL_DOMAIN}") \
        -out "$CERTS_DIR/control-public.crt"

    rm -f "$CERTS_DIR/control-public.csr"
    chmod 600 "$CERTS_DIR/control-public.key"
    chmod 644 "$CERTS_DIR/control-public.crt"

    log_info "Control public certificate generated (valid 825 days)"
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

###############################################################################
# Guided env setup (rc11 #80)
#
# Interactive prompt loop that fills in missing .env values for
# operators who'd rather click than read .env.example. Skipped when:
#   * --no-prompt is passed
#   * stdin is not a TTY (CI, piped input)
#   * .env already has every required value (idempotent re-run)
#
# Each prompt:
#   * Skips if the variable already has a non-placeholder value
#   * Offers to auto-generate strong defaults for secrets
#   * Validates URL-safety / hex / hostname constraints inline so the
#     operator can fix typos before they cause obscure runtime errors
#   * Auto-composes URL-template strings (GATEWAY_PUBLIC_TERMINAL_URL_TEMPLATE)
#     from the chosen TTY domain — operator never types {id} by hand
###############################################################################

# is_placeholder returns 0 (truthy) if the value is empty, the
# CHANGE_ME sentinel, or one of the example.com defaults from
# .env.example. Used to decide whether a prompt should fire.
is_placeholder() {
    local v="$1"
    [[ -z "$v" ]] && return 0
    [[ "$v" == CHANGE_ME* ]] && return 0
    [[ "$v" == *"example.com"* ]] && return 0
    return 1
}

# parent_domain returns the part of $1 after the first dot, or empty
# when $1 has no dot at all. Used to derive sibling-subdomain defaults
# without falling into the `${var#*.}` footgun where a no-match returns
# the WHOLE string — that would make `tty.${CONTROL_DOMAIN#*.}` for a
# single-label `localhost` resolve to `tty.localhost`, which is
# self-referential and not a useful prompt default. Round-4 review
# follow-up.
parent_domain() {
    local d="$1"
    if [[ "$d" == *.* ]]; then
        echo "${d#*.}"
    else
        echo ""
    fi
}

# write_env_var atomically updates a single key=value line in .env.
# Adds the key if missing; preserves surrounding comments/order.
#
# Atomicity: the temp file is created in the same directory as .env so
# `mv` resolves to a same-filesystem rename(2), which is atomic on
# POSIX. Default mktemp uses $TMPDIR (often a separate mount), in
# which case mv falls back to copy-then-unlink — non-atomic and also
# overwrites .env's mode/owner with the temp file's. Mode is copied
# explicitly with chmod --reference so re-runs don't downgrade .env
# off 0600.
write_env_var() {
    local key="$1" value="$2" envfile="$SCRIPT_DIR/.env"
    if grep -qE "^${key}=" "$envfile"; then
        local tmp
        tmp="$(mktemp "${envfile}.XXXXXX")"
        awk -v k="$key" -v v="$value" '
            BEGIN { found = 0 }
            $0 ~ "^"k"=" { print k"="v; found = 1; next }
            { print }
            END { if (!found) print k"="v }
        ' "$envfile" > "$tmp"
        chmod --reference="$envfile" "$tmp" 2>/dev/null || chmod 600 "$tmp"
        mv "$tmp" "$envfile"
    else
        printf '%s=%s\n' "$key" "$value" >> "$envfile"
    fi
}

# clear_env_var removes a key=value line from .env entirely. Used by
# the guided setup when the operator answers No to a feature on a
# rerun where existing values would otherwise leave the feature
# silently enabled (caught in #80 review). No-op when the key is
# absent. Same-filesystem mktemp + mode preservation as write_env_var.
clear_env_var() {
    local key="$1" envfile="$SCRIPT_DIR/.env"
    if ! grep -qE "^${key}=" "$envfile"; then
        return 0
    fi
    local tmp
    tmp="$(mktemp "${envfile}.XXXXXX")"
    awk -v k="$key" '
        $0 ~ "^"k"=" { next }
        { print }
    ' "$envfile" > "$tmp"
    chmod --reference="$envfile" "$tmp" 2>/dev/null || chmod 600 "$tmp"
    mv "$tmp" "$envfile"
}

# prompt_secret asks for a secret value, offers to generate one with
# the supplied openssl command. Stores the chosen value in $REPLY_VALUE.
# The manual-entry branch uses `read -s` so the typed secret is never
# echoed back to the terminal — the auto-generate path never traverses
# stdin so it's already silent.
prompt_secret() {
    local prompt="$1" gen_cmd="$2" current="$3"
    REPLY_VALUE=""
    if ! is_placeholder "$current"; then
        log_info "  $prompt — already set, keeping current value"
        REPLY_VALUE="$current"
        return 0
    fi
    echo ""
    read -r -p "  $prompt — generate strong value? [Y/n] " ans
    if [[ -z "$ans" || "$ans" =~ ^[Yy] ]]; then
        REPLY_VALUE="$(eval "$gen_cmd")"
        echo "    ✓ Generated."
    else
        read -r -s -p "    Enter value: " REPLY_VALUE
        # `read -s` suppresses the trailing newline; print one so the
        # subsequent log lines start on a fresh row.
        echo
    fi
}

# prompt_string asks for a free-form value, with optional default.
# Stores the chosen value in $REPLY_VALUE.
prompt_string() {
    local prompt="$1" default="$2" current="$3"
    REPLY_VALUE=""
    if ! is_placeholder "$current"; then
        log_info "  $prompt — already set ($current), keeping"
        REPLY_VALUE="$current"
        return 0
    fi
    echo ""
    if [[ -n "$default" ]]; then
        read -r -p "  $prompt [$default]: " REPLY_VALUE
        [[ -z "$REPLY_VALUE" ]] && REPLY_VALUE="$default"
    else
        read -r -p "  $prompt: " REPLY_VALUE
    fi
}

# prompt_yes_no asks a Y/n question, defaults to Yes.
prompt_yes_no() {
    local prompt="$1" default_yes="${2:-yes}"
    local hint="[Y/n]"
    [[ "$default_yes" != "yes" ]] && hint="[y/N]"
    echo ""
    read -r -p "  $prompt $hint " ans
    if [[ -z "$ans" ]]; then
        [[ "$default_yes" == "yes" ]] && return 0 || return 1
    fi
    [[ "$ans" =~ ^[Yy] ]]
}

# guided_setup runs the interactive prompt loop. Invoked from main()
# only when stdin is a TTY and --no-prompt was not passed.
guided_setup() {
    log_info "Guided setup — prompting for missing values."
    echo "  Press Ctrl-C at any time to abort. Existing .env values are kept."
    echo ""

    # Source current values so prompts can detect "already set".
    set -a
    [[ -f "$SCRIPT_DIR/.env" ]] && source "$SCRIPT_DIR/.env"
    set +a

    # --- Domains ---
    prompt_string "Control server public domain (CONTROL_DOMAIN)" "" "${CONTROL_DOMAIN:-}"
    write_env_var CONTROL_DOMAIN "$REPLY_VALUE"
    CONTROL_DOMAIN="$REPLY_VALUE"

    prompt_string "Gateway domain — agent mTLS endpoint (GATEWAY_DOMAIN)" "" "${GATEWAY_DOMAIN:-}"
    write_env_var GATEWAY_DOMAIN "$REPLY_VALUE"
    GATEWAY_DOMAIN="$REPLY_VALUE"

    # Terminal sessions are optional but recommended; offer the full set.
    if prompt_yes_no "Enable remote terminal (TTY) sessions?"; then
        # Validate distinct host inline so the rc10 collision check
        # never fires.
        local default_tty=""
        local control_parent
        control_parent="$(parent_domain "$CONTROL_DOMAIN")"
        if [[ -n "$control_parent" ]]; then
            default_tty="tty.$control_parent"
        fi
        # Single-label CONTROL_DOMAIN (e.g. `localhost`) leaves the
        # default empty so the operator types something meaningful
        # rather than accepting `tty.localhost`.
        prompt_string "TTY domain (must differ from GATEWAY_DOMAIN)" "$default_tty" "${GATEWAY_TTY_DOMAIN:-}"
        if [[ "$REPLY_VALUE" == "$GATEWAY_DOMAIN" ]]; then
            log_error "GATEWAY_TTY_DOMAIN must differ from GATEWAY_DOMAIN; aborting"
            log_error "  Traefik TCP-passthrough for mTLS would shadow the TTY HTTP router on a shared SNI."
            exit 1
        fi
        write_env_var GATEWAY_TTY_DOMAIN "$REPLY_VALUE"
        local tty_dom="$REPLY_VALUE"

        # Auto-compose the URL template. Operator never types {id}.
        write_env_var GATEWAY_PUBLIC_TERMINAL_URL_TEMPLATE "wss://${tty_dom}/gw/{id}/terminal"
        echo "    ✓ GATEWAY_PUBLIC_TERMINAL_URL_TEMPLATE composed automatically."

        # The TTY HTTP listener inside the container — Traefik
        # terminates public TLS and forwards cleartext.
        write_env_var GATEWAY_WEB_LISTEN_ADDR ":8443"
        echo "    ✓ GATEWAY_WEB_LISTEN_ADDR set to :8443."
    else
        # Operator chose No. If an existing .env already has any of
        # these set (e.g. a rerun where terminals were previously
        # enabled), simply skipping leaves the feature on — the
        # gateway would still publish its terminal URL on next boot.
        # Clear all three explicitly so the No answer matches the
        # observable state. Caught in #80 review.
        local was_enabled=0
        for k in GATEWAY_TTY_DOMAIN GATEWAY_PUBLIC_TERMINAL_URL_TEMPLATE GATEWAY_WEB_LISTEN_ADDR; do
            if grep -qE "^${k}=" "$SCRIPT_DIR/.env" 2>/dev/null; then
                was_enabled=1
                clear_env_var "$k"
            fi
        done
        if [[ "$was_enabled" -eq 1 ]]; then
            log_info "  Terminal sessions disabled — cleared GATEWAY_TTY_DOMAIN, GATEWAY_PUBLIC_TERMINAL_URL_TEMPLATE, and GATEWAY_WEB_LISTEN_ADDR from .env."
        else
            log_info "  Terminal sessions disabled — none of the terminal env vars were set, nothing to clear."
        fi
    fi

    prompt_string "Email for Let's Encrypt notifications (ACME_EMAIL)" "" "${ACME_EMAIL:-}"
    write_env_var ACME_EMAIL "$REPLY_VALUE"

    # --- Image tag ---
    prompt_string "Image tag — :latest, :latest-rc, or pin to vYYYY.MM (IMAGE_TAG)" "latest" "${IMAGE_TAG:-}"
    write_env_var IMAGE_TAG "$REPLY_VALUE"

    # --- Secrets ---
    echo ""
    log_info "Generating / collecting secrets…"

    prompt_secret "PostgreSQL password (POSTGRES_PASSWORD)" "openssl rand -base64 32" "${POSTGRES_PASSWORD:-}"
    write_env_var POSTGRES_PASSWORD "$REPLY_VALUE"

    # Indexer password MUST be URL-safe — used in a libpq DSN by the
    # indexer. Hex output is the safest generator for this constraint.
    prompt_secret "Indexer DB password (INDEXER_POSTGRES_PASSWORD, must be URL-safe)" "openssl rand -hex 32" "${INDEXER_POSTGRES_PASSWORD:-}"
    if [[ "$REPLY_VALUE" =~ [^A-Za-z0-9_.-] ]]; then
        log_error "INDEXER_POSTGRES_PASSWORD contains URL-unsafe characters: ${BASH_REMATCH[0]}"
        log_error "  Use 'openssl rand -hex 32' or pick alphanumeric only. Aborting."
        exit 1
    fi
    write_env_var INDEXER_POSTGRES_PASSWORD "$REPLY_VALUE"

    prompt_secret "Valkey password (VALKEY_PASSWORD)" "openssl rand -base64 32" "${VALKEY_PASSWORD:-}"
    write_env_var VALKEY_PASSWORD "$REPLY_VALUE"

    prompt_secret "JWT secret (JWT_SECRET, min 32 chars)" "openssl rand -base64 48" "${JWT_SECRET:-}"
    if [[ ${#REPLY_VALUE} -lt 32 ]]; then
        log_error "JWT_SECRET must be at least 32 characters; got ${#REPLY_VALUE}. Aborting."
        exit 1
    fi
    write_env_var JWT_SECRET "$REPLY_VALUE"

    # Encryption key must be exactly 64 hex chars (32 bytes).
    prompt_secret "Encryption key for IdP/LUKS secrets (CONTROL_ENCRYPTION_KEY, 64 hex chars)" "openssl rand -hex 32" "${CONTROL_ENCRYPTION_KEY:-}"
    if [[ ! "$REPLY_VALUE" =~ ^[0-9a-fA-F]{64}$ ]]; then
        log_error "CONTROL_ENCRYPTION_KEY must be exactly 64 hex characters; got ${#REPLY_VALUE} chars. Aborting."
        exit 1
    fi
    write_env_var CONTROL_ENCRYPTION_KEY "$REPLY_VALUE"

    # --- Admin account ---
    # admin@<parent-domain> if CONTROL_DOMAIN has a dot; admin@<full>
    # for single-label cases (admin@localhost is a valid local-delivery
    # address for those deployments).
    local admin_parent
    admin_parent="$(parent_domain "$CONTROL_DOMAIN")"
    local default_email
    if [[ -n "$admin_parent" ]]; then
        default_email="admin@$admin_parent"
    else
        default_email="admin@$CONTROL_DOMAIN"
    fi
    prompt_string "Bootstrap admin email (ADMIN_EMAIL)" "$default_email" "${ADMIN_EMAIL:-}"
    write_env_var ADMIN_EMAIL "$REPLY_VALUE"

    prompt_secret "Bootstrap admin password (ADMIN_PASSWORD)" "openssl rand -base64 24" "${ADMIN_PASSWORD:-}"
    write_env_var ADMIN_PASSWORD "$REPLY_VALUE"
    local admin_pass="$REPLY_VALUE"

    echo ""
    log_info "Guided setup complete. .env updated."
    if ! is_placeholder "$admin_pass"; then
        log_warn "Bootstrap admin password — write this down NOW; it's not shown again:"
        echo ""
        echo "    Email:    $ADMIN_EMAIL"
        echo "    Password: $admin_pass"
        echo ""
        log_warn "The bootstrap admin is for first-login only — see deploy/.env.example for details."
    fi
    echo ""
}

# parse_flags reads our own --no-prompt before falling through to the
# rest of setup.sh. Kept simple — no other flags supported.
NO_PROMPT=0
for arg in "$@"; do
    case "$arg" in
        --no-prompt) NO_PROMPT=1 ;;
        -h|--help)
            cat <<EOF
Usage: ./setup.sh [--no-prompt]

  --no-prompt   Skip the interactive guided env setup; run cert
                generation against the existing .env only. Equivalent
                to running with stdin redirected from /dev/null.
EOF
            exit 0
            ;;
        *)
            # Reject typos like --noprompt explicitly. Silent
            # acceptance was a footgun: `./setup.sh --noprompt` on a
            # fresh .env would run guided mode (CHANGE_ME values)
            # and confuse the operator about why prompts appeared.
            log_error "Unknown argument: $arg"
            log_error "  See: $0 --help"
            exit 2
            ;;
    esac
done

main() {
    log_info "Power Manage Server Setup"
    echo ""

    # Guided mode runs only on a TTY when --no-prompt wasn't passed.
    # Falling back to non-prompt automatically when stdin is piped or
    # redirected preserves CI / install.sh behavior.
    if [[ "$NO_PROMPT" -eq 0 && -t 0 ]]; then
        guided_setup
    else
        log_info "Non-interactive mode — skipping guided setup. Validating .env directly."
    fi

    check_env
    generate_ca
    generate_gateway_cert
    generate_control_cert
    generate_control_public_cert

    # Data directories need permissions that let the container
    # users (postgres uid 70, valkey uid 999, traefik uid 0)
    # write into the bind-mounted volumes. The script-wide
    # `umask 077` at the top protects the certs/ tree; for data/
    # we reset to 022 so the directories are 755 and the
    # containers can initialise them.
    (umask 022 && mkdir -p "$DATA_DIR/postgres" "$DATA_DIR/valkey" "$DATA_DIR/traefik")
    chmod 755 "$DATA_DIR/postgres" "$DATA_DIR/valkey" "$DATA_DIR/traefik"
    log_info "Created data directories: $DATA_DIR/{postgres,valkey,traefik}"

    show_instructions
}

main "$@"
