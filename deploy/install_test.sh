#!/usr/bin/env bash

set -euo pipefail

DEPLOY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# install.sh's prerequisites are stubbed rather than required. That is what
# makes these tests hermetic in the way that matters: the stub curl records the
# attempt and fetches nothing, so "was a release downloaded" is a fact the
# assertions read out of a file instead of a network round trip they hope
# failed.
STUB_ROOT="$(mktemp -d)"
FIXTURE_ROOT="$(mktemp -d)"
export CALL_LOG="$STUB_ROOT/calls"
trap 'rm -rf "$STUB_ROOT" "$FIXTURE_ROOT"' EXIT

stub_command() {
    local name="$1" body="$2"
    mkdir -p "$STUB_ROOT/bin"
    cat > "$STUB_ROOT/bin/$name" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf '$name %s\n' "\$*" >> "\$CALL_LOG"
$body
EOF
    chmod +x "$STUB_ROOT/bin/$name"
}

# curl must never succeed here: a case that downloaded a real release would
# pass or fail for reasons this file does not control.
stub_command curl 'exit 1'
stub_command tar 'exit 0'
stub_command docker 'exit 0'
stub_command openssl 'exit 0'

new_install_dir() {
    mktemp -d "$FIXTURE_ROOT/XXXXXX"
}

# Every input install.sh reads comes from its environment, so each case is
# given a complete valid set and overrides only the variable it is about.
# GITHUB_REPOSITORY names a host that cannot exist as a second guard: were the
# stub ever bypassed, the download would fail rather than reach a real release.
run_install() {
    local directory="$1"
    shift
    : > "$CALL_LOG"
    env -u RELEASE_TAG -u ACME_CHALLENGE -u ACME_DNS_PROVIDER \
        PATH="$STUB_ROOT/bin:$PATH" \
        INSTALL_DIR="$directory" \
        CONTROL_DOMAIN=manage.example.test \
        AGENT_DOMAIN=agents.example.test \
        ACME_EMAIL=admin@example.test \
        GITHUB_REPOSITORY=power-manage.invalid/server \
        "$@" \
        bash "$DEPLOY_DIR/install.sh"
}

assert_no_download() {
    local attempts
    attempts="$(grep -c '^curl ' "$CALL_LOG" || true)"
    [[ "$attempts" == 0 ]] || {
        printf 'install.sh attempted %s download(s):\n%s\n' "$attempts" "$(grep '^curl ' "$CALL_LOG")" >&2
        return 1
    }
}

# A refused install must leave the directory it was pointed at exactly as it
# found it, so the operator corrects the variable and runs it again rather than
# clearing a half-unpacked tree first.
assert_install_dir_empty() {
    local directory="$1" leftover
    leftover="$(find "$directory" -mindepth 1 -print -quit)"
    [[ -z "$leftover" ]] || {
        printf 'refused run wrote into the install directory: %s\n' "$leftover" >&2
        return 1
    }
}

# A default of `main` installs whatever that branch pointed at on the day it
# ran, which is not an installation anyone can reproduce or attest. Unset must
# stop the run, and stop it before anything is fetched.
test_missing_release_tag_refuses_before_downloading() {
    local directory="$1" output
    if output="$(run_install "$directory" 2>&1)"; then
        printf 'install.sh installed something with RELEASE_TAG unset\n' >&2
        return 1
    fi
    assert_no_download
    grep -Fq 'RELEASE_TAG' <<<"$output" || {
        printf 'refusal does not name RELEASE_TAG: %s\n' "$output" >&2
        return 1
    }
    # The message has to carry an immutable example. An operator told only "set
    # RELEASE_TAG" reaches for the branch name that used to be the default.
    grep -Eq 'RELEASE_TAG=v[0-9]' <<<"$output" || {
        printf 'refusal does not show a release-tag example: %s\n' "$output" >&2
        return 1
    }
    assert_install_dir_empty "$directory"
}

# Every input is judged before the release is fetched, so an operator who
# mistyped one gets the message and an untouched directory rather than an
# unpacked tree and a failure inside setup.sh.
test_invalid_challenge_refuses_before_downloading() {
    local directory="$1" output
    if output="$(run_install "$directory" RELEASE_TAG=v2026.08.09-rc2 ACME_CHALLENGE=bogus 2>&1)"; then
        printf 'install.sh accepted an unusable ACME challenge\n' >&2
        return 1
    fi
    assert_no_download
    grep -Fq 'ACME_CHALLENGE must be http01 or dns01' <<<"$output" || {
        printf 'refusal does not name the challenge problem: %s\n' "$output" >&2
        return 1
    }
    assert_install_dir_empty "$directory"
}

# The two cases above assert that no download happened, which would hold just
# as well if install.sh could never download at all. A complete, valid
# environment has to reach the fetch, and reach it with the tag it was given.
test_complete_environment_reaches_the_release_tag() {
    local directory="$1"
    if run_install "$directory" RELEASE_TAG=v2026.08.09-rc2 >/dev/null 2>&1; then
        printf 'the stubbed download succeeded; the negative cases prove nothing\n' >&2
        return 1
    fi
    grep -Fq 'refs/tags/v2026.08.09-rc2.tar.gz' "$CALL_LOG" || {
        printf 'install.sh did not request the release tag:\n%s\n' "$(cat "$CALL_LOG")" >&2
        return 1
    }
}

test_missing_release_tag_refuses_before_downloading "$(new_install_dir)"
printf 'PASS unset RELEASE_TAG refused before any download\n'
test_invalid_challenge_refuses_before_downloading "$(new_install_dir)"
printf 'PASS unusable ACME challenge refused before any download\n'
test_complete_environment_reaches_the_release_tag "$(new_install_dir)"
printf 'PASS a complete environment fetches the named release tag\n'
