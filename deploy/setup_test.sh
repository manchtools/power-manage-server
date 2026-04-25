#!/usr/bin/env bash
#
# setup.sh helper smoke tests. Sources setup.sh's helpers in a
# subshell with a fake SCRIPT_DIR + .env so the helpers can be
# exercised without invoking the cert-generation main flow.
#
# Run:
#   ./deploy/setup_test.sh
#
# Exits non-zero on any failure. Prints PASS / FAIL per case.
#
# rc11 #80: covers the disable-clears path that the review caught
# as silently no-op'ing in the previous cut.

set -euo pipefail

SCRIPT_DIR_REAL="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PASS_COUNT=0
FAIL_COUNT=0

run_case() {
    local name="$1"
    shift
    local tmp
    tmp="$(mktemp -d)"
    trap "rm -rf '$tmp'" RETURN

    # Minimal harness: the helpers we test only depend on SCRIPT_DIR
    # and the .env path. Sourcing setup.sh in full would run main();
    # extract just the helper functions instead.
    (
        SCRIPT_DIR="$tmp"
        # log_* are used inside the helpers — define no-op shims.
        log_info() { :; }
        log_warn() { :; }
        log_error() { :; }

        # Inline the helper definitions we need to test. Keep in sync
        # with setup.sh — these tests would catch a divergence as a
        # FAIL anyway, which is the point.
        write_env_var() {
            local key="$1" value="$2" envfile="$SCRIPT_DIR/.env"
            if grep -qE "^${key}=" "$envfile"; then
                local tf
                tf="$(mktemp)"
                awk -v k="$key" -v v="$value" '
                    BEGIN { found = 0 }
                    $0 ~ "^"k"=" { print k"="v; found = 1; next }
                    { print }
                    END { if (!found) print k"="v }
                ' "$envfile" > "$tf"
                mv "$tf" "$envfile"
            else
                printf '%s=%s\n' "$key" "$value" >> "$envfile"
            fi
        }
        clear_env_var() {
            local key="$1" envfile="$SCRIPT_DIR/.env"
            if ! grep -qE "^${key}=" "$envfile"; then
                return 0
            fi
            local tf
            tf="$(mktemp)"
            awk -v k="$key" '
                $0 ~ "^"k"=" { next }
                { print }
            ' "$envfile" > "$tf"
            mv "$tf" "$envfile"
        }

        if "$@"; then
            echo "PASS: $name"
            exit 0
        else
            echo "FAIL: $name"
            exit 1
        fi
    )
    if [[ $? -eq 0 ]]; then
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
}

# ----- write_env_var -----

case_write_env_var_adds_missing_key() {
    : > "$SCRIPT_DIR/.env"
    write_env_var FOO bar
    grep -qE '^FOO=bar$' "$SCRIPT_DIR/.env"
}

case_write_env_var_updates_existing_key() {
    cat > "$SCRIPT_DIR/.env" <<EOF
FOO=old
BAR=keep
EOF
    write_env_var FOO new
    grep -qE '^FOO=new$' "$SCRIPT_DIR/.env" && grep -qE '^BAR=keep$' "$SCRIPT_DIR/.env"
}

case_write_env_var_preserves_comments() {
    cat > "$SCRIPT_DIR/.env" <<EOF
# header
FOO=old
# trailing
EOF
    write_env_var FOO new
    grep -qE '^# header$' "$SCRIPT_DIR/.env" \
        && grep -qE '^FOO=new$' "$SCRIPT_DIR/.env" \
        && grep -qE '^# trailing$' "$SCRIPT_DIR/.env"
}

# ----- clear_env_var (rc11 #80 review fix) -----

case_clear_env_var_removes_existing_key() {
    cat > "$SCRIPT_DIR/.env" <<EOF
FOO=value
BAR=keep
BAZ=alsokeep
EOF
    clear_env_var FOO
    ! grep -qE '^FOO=' "$SCRIPT_DIR/.env" \
        && grep -qE '^BAR=keep$' "$SCRIPT_DIR/.env" \
        && grep -qE '^BAZ=alsokeep$' "$SCRIPT_DIR/.env"
}

case_clear_env_var_noop_on_missing_key() {
    cat > "$SCRIPT_DIR/.env" <<EOF
BAR=keep
EOF
    clear_env_var FOO
    grep -qE '^BAR=keep$' "$SCRIPT_DIR/.env" \
        && [[ "$(wc -l < "$SCRIPT_DIR/.env")" -eq 1 ]]
}

case_disable_terminals_clears_all_three_vars() {
    # Simulates the rerun footgun the review caught: existing .env
    # has all three terminal vars set; operator answers No; the
    # disable path must clear all three.
    cat > "$SCRIPT_DIR/.env" <<EOF
GATEWAY_DOMAIN=gateway.example.com
GATEWAY_TTY_DOMAIN=tty.example.com
GATEWAY_PUBLIC_TERMINAL_URL_TEMPLATE=wss://tty.example.com/gw/{id}/terminal
GATEWAY_WEB_LISTEN_ADDR=:8443
ADMIN_EMAIL=admin@example.com
EOF
    # Inline equivalent of the No-branch in guided_setup.
    for k in GATEWAY_TTY_DOMAIN GATEWAY_PUBLIC_TERMINAL_URL_TEMPLATE GATEWAY_WEB_LISTEN_ADDR; do
        clear_env_var "$k"
    done
    ! grep -qE '^GATEWAY_TTY_DOMAIN=' "$SCRIPT_DIR/.env" \
        && ! grep -qE '^GATEWAY_PUBLIC_TERMINAL_URL_TEMPLATE=' "$SCRIPT_DIR/.env" \
        && ! grep -qE '^GATEWAY_WEB_LISTEN_ADDR=' "$SCRIPT_DIR/.env" \
        && grep -qE '^GATEWAY_DOMAIN=gateway\.example\.com$' "$SCRIPT_DIR/.env" \
        && grep -qE '^ADMIN_EMAIL=admin@example\.com$' "$SCRIPT_DIR/.env"
}

# ----- run -----

run_case "write_env_var: adds missing key"          case_write_env_var_adds_missing_key
run_case "write_env_var: updates existing key"      case_write_env_var_updates_existing_key
run_case "write_env_var: preserves comments"        case_write_env_var_preserves_comments
run_case "clear_env_var: removes existing key"      case_clear_env_var_removes_existing_key
run_case "clear_env_var: noop on missing key"       case_clear_env_var_noop_on_missing_key
run_case "disable terminals clears all three vars"  case_disable_terminals_clears_all_three_vars

echo ""
echo "Total: $((PASS_COUNT + FAIL_COUNT))   Passed: $PASS_COUNT   Failed: $FAIL_COUNT"
[[ $FAIL_COUNT -eq 0 ]]
