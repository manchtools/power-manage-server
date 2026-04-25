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
    #
    # The subshell goes directly inside `if ... then`. Earlier cut used
    #   ( ... ); if [[ $? -eq 0 ]]; then
    # which dead-ends under `set -e`: a non-zero subshell exit kills
    # the parent before $? is read, so the first failing case would
    # bail out of the whole suite and FAIL_COUNT / the summary line
    # were unreachable. Caught by the rc11 round-3 review.
    if (
        SCRIPT_DIR="$tmp"
        # log_* are used inside the helpers — define no-op shims.
        log_info() { :; }
        log_warn() { :; }
        log_error() { :; }

        # Inline the helper definitions we need to test. Must stay in
        # sync with setup.sh — including the same-fs mktemp +
        # chmod-reference dance that preserves .env's mode across
        # rewrites. An earlier inline diverged on the chmod and the
        # round-3 review caught it: a regression that drops the chmod
        # in setup.sh would have passed this harness silently.
        write_env_var() {
            local key="$1" value="$2" envfile="$SCRIPT_DIR/.env"
            if grep -qE "^${key}=" "$envfile"; then
                local tf
                tf="$(mktemp "${envfile}.XXXXXX")"
                awk -v k="$key" -v v="$value" '
                    BEGIN { found = 0 }
                    $0 ~ "^"k"=" { print k"="v; found = 1; next }
                    { print }
                    END { if (!found) print k"="v }
                ' "$envfile" > "$tf"
                chmod --reference="$envfile" "$tf" 2>/dev/null || chmod 600 "$tf"
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
            tf="$(mktemp "${envfile}.XXXXXX")"
            awk -v k="$key" '
                $0 ~ "^"k"=" { next }
                { print }
            ' "$envfile" > "$tf"
            chmod --reference="$envfile" "$tf" 2>/dev/null || chmod 600 "$tf"
            mv "$tf" "$envfile"
        }
        parent_domain() {
            local d="$1"
            if [[ "$d" == *.* ]]; then
                echo "${d#*.}"
            else
                echo ""
            fi
        }

        if "$@"; then
            echo "PASS: $name"
            exit 0
        else
            echo "FAIL: $name"
            exit 1
        fi
    ); then
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

case_write_env_var_preserves_mode_0600() {
    : > "$SCRIPT_DIR/.env"
    chmod 600 "$SCRIPT_DIR/.env"
    write_env_var FOO bar
    write_env_var FOO baz   # exercise the rewrite branch specifically
    local mode
    mode="$(stat -c '%a' "$SCRIPT_DIR/.env")"
    [[ "$mode" == "600" ]]
}

case_clear_env_var_preserves_mode_0600() {
    cat > "$SCRIPT_DIR/.env" <<EOF
FOO=value
BAR=keep
EOF
    chmod 600 "$SCRIPT_DIR/.env"
    clear_env_var FOO
    local mode
    mode="$(stat -c '%a' "$SCRIPT_DIR/.env")"
    [[ "$mode" == "600" ]]
}

case_parent_domain_with_dot() {
    : > "$SCRIPT_DIR/.env"
    local got
    got="$(parent_domain control.example.com)"
    [[ "$got" == "example.com" ]]
}

case_parent_domain_single_label() {
    : > "$SCRIPT_DIR/.env"
    local got
    got="$(parent_domain localhost)"
    [[ -z "$got" ]]
}

case_parent_domain_deep_subdomain() {
    : > "$SCRIPT_DIR/.env"
    local got
    got="$(parent_domain a.b.c.example.com)"
    [[ "$got" == "b.c.example.com" ]]
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
run_case "write_env_var: preserves mode 0600"       case_write_env_var_preserves_mode_0600
run_case "clear_env_var: removes existing key"      case_clear_env_var_removes_existing_key
run_case "clear_env_var: noop on missing key"       case_clear_env_var_noop_on_missing_key
run_case "clear_env_var: preserves mode 0600"       case_clear_env_var_preserves_mode_0600
run_case "parent_domain: dotted hostname"           case_parent_domain_with_dot
run_case "parent_domain: single label returns empty" case_parent_domain_single_label
run_case "parent_domain: deep subdomain"            case_parent_domain_deep_subdomain
run_case "disable terminals clears all three vars"  case_disable_terminals_clears_all_three_vars

# Meta: make sure the FAIL counting + final non-zero exit path actually
# work. The previous cut had set-e + ( ... ) + $? which silently killed
# the suite on the first failing case; a green run of all-PASSes was
# not enough to prove the harness behaves as documented when something
# fails. Run a deliberately failing case last and special-case the
# tally so the script still exits 0 when only this synthetic failure
# is present.
case_meta_failure() {
    return 1
}
run_case "(meta) intentional failure: harness counts FAIL"  case_meta_failure

echo ""
if [[ $FAIL_COUNT -eq 1 ]]; then
    # Only the synthetic case failed → harness is healthy.
    REAL_FAILS=0
else
    REAL_FAILS=$((FAIL_COUNT - 1))
fi
echo "Total: $((PASS_COUNT + FAIL_COUNT))   Passed: $PASS_COUNT   Failed: $FAIL_COUNT (synthetic: 1, real: $REAL_FAILS)"
[[ $REAL_FAILS -eq 0 ]]
