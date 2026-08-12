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

# The guided tests drive install.sh through a pseudo-terminal, because the
# prompts must appear only for a human at a terminal and `-t 0` cannot be
# faked through a pipe.
for required in python3 timeout; do
    command -v "$required" >/dev/null 2>&1 \
        || { printf '%s is required for the guided tests\n' "$required" >&2; exit 1; }
done

# The dns01 case has to get past download and unpacking to reach the
# credentials stop, so it gets its own stub set: a curl that serves a fixture
# release tarball, and the real tar to unpack it. docker and openssl stay
# stubbed. The fixture setup.sh records that it ran, which the test asserts
# never happens.
FIXTURE_SOURCE="$FIXTURE_ROOT/power-manage-server-fixture"
FIXTURE_TARBALL="$FIXTURE_ROOT/release.tar.gz"
SKEW_TARBALL="$FIXTURE_ROOT/release-skew.tar.gz"
mkdir -p "$FIXTURE_SOURCE/deploy"
: > "$FIXTURE_SOURCE/deploy/compose.yml"
cat > "$FIXTURE_SOURCE/deploy/setup.sh" <<'EOF'
#!/usr/bin/env bash
printf 'setup-ran\n' > setup-ran-marker
EOF
chmod +x "$FIXTURE_SOURCE/deploy/setup.sh"
# The skew tarball ships WITHOUT the running install.sh: a tree whose entry
# script differs from the one executing is tonight's version-skew trap and
# must be warned about. The main tarball then gains a byte-identical copy,
# which is what a matching release looks like and must stay silent.
tar -czf "$SKEW_TARBALL" -C "$FIXTURE_ROOT" "$(basename "$FIXTURE_SOURCE")"
cp "$DEPLOY_DIR/install.sh" "$FIXTURE_SOURCE/deploy/install.sh"
tar -czf "$FIXTURE_TARBALL" -C "$FIXTURE_ROOT" "$(basename "$FIXTURE_SOURCE")"

mkdir -p "$STUB_ROOT/download-bin"
cat > "$STUB_ROOT/download-bin/curl" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf 'curl %s\n' "\$*" >> "\$CALL_LOG"
target=""
previous=""
for argument in "\$@"; do
    [[ "\$previous" == -o ]] && target="\$argument"
    previous="\$argument"
done
cp "$FIXTURE_TARBALL" "\$target"
EOF
chmod +x "$STUB_ROOT/download-bin/curl"
cp "$STUB_ROOT/bin/docker" "$STUB_ROOT/bin/openssl" "$STUB_ROOT/download-bin/"

# The loopback-archive path shells out to filesystem tooling that a test must
# not really run: creating images, making filesystems, and mounting are root
# operations whose effect the assertions read from the call log instead.
# mountpoint reports "not mounted" so the preparation branch is always taken.
for tool in truncate mkfs.ext4 mount; do
    stub_command "$tool" 'exit 0'
done
stub_command mountpoint 'exit 1'
cp "$STUB_ROOT/bin/truncate" "$STUB_ROOT/bin/mkfs.ext4" "$STUB_ROOT/bin/mount" \
    "$STUB_ROOT/bin/mountpoint" "$STUB_ROOT/download-bin/"

# A second download stub set that serves the skew tarball.
mkdir -p "$STUB_ROOT/skew-bin"
sed "s|$FIXTURE_TARBALL|$SKEW_TARBALL|" "$STUB_ROOT/download-bin/curl" > "$STUB_ROOT/skew-bin/curl"
chmod +x "$STUB_ROOT/skew-bin/curl"
cp "$STUB_ROOT/bin/docker" "$STUB_ROOT/bin/openssl" "$STUB_ROOT/skew-bin/"

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

# A guided run receives its answers on a pseudo-terminal and must behave like
# the same values passed through the environment. The answers arrive as one
# line per prompt; a re-asked prompt consumes the next line. An answer script
# that is one line short blocks on the pty until timeout kills the run, which
# is the failure mode that catches an unexpected extra prompt.
run_install_guided() {
    local directory="$1" answers="$2" bin_directory="$3" fstab="${4:-/dev/null}"
    : > "$CALL_LOG"
    printf '%s' "$answers" | timeout 30 env \
        -u RELEASE_TAG -u ACME_CHALLENGE -u ACME_DNS_PROVIDER \
        -u CONTROL_DOMAIN -u AGENT_DOMAIN -u ACME_EMAIL -u ARCHIVE_LOOPBACK \
        PATH="$bin_directory:$PATH" \
        INSTALL_DIR="$directory" \
        GITHUB_REPOSITORY=power-manage.invalid/server \
        FSTAB_FILE="$fstab" \
        python3 -c 'import os, pty, sys; sys.exit(os.waitstatus_to_exitcode(pty.spawn(sys.argv[1:])))' \
        bash "$DEPLOY_DIR/install.sh"
}

# Without a terminal nothing may prompt: a missing value keeps refusing with
# the message an unattended caller scripts against, and nothing is fetched.
test_missing_domain_without_terminal_still_refuses() {
    local directory="$1" output
    : > "$CALL_LOG"
    if output="$(env -u CONTROL_DOMAIN \
        PATH="$STUB_ROOT/bin:$PATH" \
        INSTALL_DIR="$directory" \
        AGENT_DOMAIN=agents.example.test \
        ACME_EMAIL=admin@example.test \
        RELEASE_TAG=v2026.08.09-rc2 \
        GITHUB_REPOSITORY=power-manage.invalid/server \
        bash "$DEPLOY_DIR/install.sh" </dev/null 2>&1)"; then
        printf 'install.sh proceeded without CONTROL_DOMAIN and without a terminal\n' >&2
        return 1
    fi
    grep -Fq 'set CONTROL_DOMAIN' <<<"$output" || {
        printf 'refusal does not name CONTROL_DOMAIN: %s\n' "$output" >&2
        return 1
    }
    assert_no_download
    assert_install_dir_empty "$directory"
}

# A terminal with none of the values set is interviewed for them, an invalid
# answer is re-asked rather than fatal, and the answers drive the same fetch
# the environment otherwise would.
test_guided_answers_reach_the_release_tag() {
    local directory="$1" output answers
    answers=$'not_a_domain\nmanage.example.test\nagents.example.test\nadmin@example.test\nv2026.08.09-rc2\n\n\n'
    output="$(run_install_guided "$directory" "$answers" "$STUB_ROOT/bin" 2>&1)" && {
        printf 'the stubbed download succeeded; the guided case proves nothing\n' >&2
        return 1
    }
    grep -Fq 'could not download' <<<"$output" || {
        printf 'guided run did not reach the download step: %s\n' "$output" >&2
        return 1
    }
    grep -Fq 'refs/tags/v2026.08.09-rc2.tar.gz' "$CALL_LOG" || {
        printf 'guided run did not request the answered release tag:\n%s\n' "$(cat "$CALL_LOG")" >&2
        return 1
    }
    grep -Fq 'fully-qualified hostname' <<<"$output" || {
        printf 'invalid hostname answer was not re-asked with a hint: %s\n' "$output" >&2
        return 1
    }
    grep -Fq 'dns01' <<<"$output" || {
        printf 'certificate choice was never offered: %s\n' "$output" >&2
        return 1
    }
}

# The dns01 answer must never lead to a credential prompt. The run renders
# .env from the answers, prepares the empty 0600 credentials file, marks it
# for the operator to paste the secret into, and stops before setup.sh.
test_guided_dns01_marks_the_credential_for_self_pasting() {
    local directory="$1" output answers
    answers=$'manage.example.test\nagents.example.test\nadmin@example.test\nv2026.08.09-rc2\ndns01\nhetzner\n\n'
    output="$(run_install_guided "$directory" "$answers" "$STUB_ROOT/download-bin" 2>&1)" && {
        printf 'guided dns01 run finished although the credential is missing\n' >&2
        return 1
    }
    for expected in \
        'CONTROL_DOMAIN=manage.example.test' \
        'AGENT_DOMAIN=agents.example.test' \
        'ACME_EMAIL=admin@example.test' \
        'ACME_CHALLENGE=dns01' \
        'ACME_DNS_PROVIDER=hetzner' \
        'IMAGE_TAG=2026.08.09-rc2'; do
        grep -Fxq "$expected" "$directory/.env" || {
            printf 'guided .env is missing %s:\n%s\n' "$expected" "$(cat "$directory/.env")" >&2
            return 1
        }
    done
    [[ -f "$directory/config/traefik-dns.env" && ! -s "$directory/config/traefik-dns.env" ]] || {
        printf 'the empty credentials file was not prepared\n' >&2
        return 1
    }
    [[ "$(stat -c '%a' "$directory/config/traefik-dns.env")" == 600 ]] || {
        printf 'credentials file is not mode 600\n' >&2
        return 1
    }
    grep -Fq 'ACTION REQUIRED' <<<"$output" || {
        printf 'the stop does not mark the credential step: %s\n' "$output" >&2
        return 1
    }
    grep -Fq 'traefik-dns.env' <<<"$output" || {
        printf 'the stop does not name the credentials file: %s\n' "$output" >&2
        return 1
    }
    [[ ! -e "$directory/setup-ran-marker" ]] || {
        printf 'setup.sh ran although the credential is missing\n' >&2
        return 1
    }
    grep -Eq 'docker compose (pull|up)' "$CALL_LOG" && {
        printf 'the stack was touched although the credential is missing:\n%s\n' "$(cat "$CALL_LOG")" >&2
        return 1
    }
    grep -Fq 'differs from the one inside release' <<<"$output" && {
        printf 'a matching release tree must not raise the skew warning: %s\n' "$output" >&2
        return 1
    }
    grep -Fq 'must point at this host' <<<"$output" || {
        printf 'the credential stop does not remind about the DNS records: %s\n' "$output" >&2
        return 1
    }
    return 0
}

# The entry script evolves with main while RELEASE_TAG pins the tree it
# installs. A tree whose own deploy/install.sh differs from the running script
# may silently ignore options the script offered, so the mismatch must be
# named — while the install still proceeds to its normal stopping point.
test_version_skew_between_script_and_tree_warns() {
    local directory="$1" output
    : > "$CALL_LOG"
    if output="$(run_install "$directory" \
        RELEASE_TAG=v2026.08.09-rc2 ACME_CHALLENGE=dns01 ACME_DNS_PROVIDER=hetzner \
        PATH="$STUB_ROOT/skew-bin:$PATH" 2>&1)"; then
        printf 'skewed dns01 run finished although the credential is missing\n' >&2
        return 1
    fi
    grep -Fq 'differs from the one inside release' <<<"$output" || {
        printf 'the version skew was not named: %s\n' "$output" >&2
        return 1
    }
    grep -Fq 'ACTION REQUIRED' <<<"$output" || {
        printf 'the skew warning must not replace the credential stop: %s\n' "$output" >&2
        return 1
    }
}

# The dangerous single-node choice never weakens control's own archive check:
# it satisfies it by preparing a loopback filesystem at data/backups. The run
# must say so loudly, prepare the image idempotently, persist the mount, and
# then proceed all the way to the stack.
test_guided_loopback_archive_prepares_same_disk_storage() {
    local directory="$1" output answers fstab
    fstab="$FIXTURE_ROOT/fstab.$$"
    : > "$fstab"
    answers=$'manage.example.test\nagents.example.test\nadmin@example.test\nv2026.08.09-rc2\n\nloopback\n'
    output="$(run_install_guided "$directory" "$answers" "$STUB_ROOT/download-bin" "$fstab" 2>&1)" || {
        printf 'guided loopback run failed: %s\n' "$output" >&2
        return 1
    }
    grep -Fq 'DANGEROUS' <<<"$output" || {
        printf 'the loopback choice was accepted without naming the danger: %s\n' "$output" >&2
        return 1
    }
    grep -Eq 'mkfs\.ext4 .*backups\.img' "$CALL_LOG" || {
        printf 'no filesystem was created for the loopback archive:\n%s\n' "$(cat "$CALL_LOG")" >&2
        return 1
    }
    grep -Eq 'mount .*backups\.img' "$CALL_LOG" || {
        printf 'the loopback archive was never mounted:\n%s\n' "$(cat "$CALL_LOG")" >&2
        return 1
    }
    grep -Fq "$directory/data/backups.img" "$fstab" || {
        printf 'the loopback mount was not persisted for reboots:\n%s\n' "$(cat "$fstab")" >&2
        return 1
    }
    [[ -e "$directory/setup-ran-marker" ]] || {
        printf 'setup.sh never ran although the archive was prepared\n' >&2
        return 1
    }
    grep -Fq 'docker compose pull' "$CALL_LOG" || {
        printf 'the stack was never started:\n%s\n' "$(cat "$CALL_LOG")" >&2
        return 1
    }
    grep -Fq 'must point at this host' <<<"$output" || {
        printf 'the success output does not remind about the DNS records: %s\n' "$output" >&2
        return 1
    }
}

test_missing_release_tag_refuses_before_downloading "$(new_install_dir)"
printf 'PASS unset RELEASE_TAG refused before any download\n'
test_invalid_challenge_refuses_before_downloading "$(new_install_dir)"
printf 'PASS unusable ACME challenge refused before any download\n'
test_complete_environment_reaches_the_release_tag "$(new_install_dir)"
printf 'PASS a complete environment fetches the named release tag\n'
test_missing_domain_without_terminal_still_refuses "$(new_install_dir)"
printf 'PASS missing value without a terminal refuses instead of prompting\n'
test_guided_answers_reach_the_release_tag "$(new_install_dir)"
printf 'PASS guided answers drive the fetch and invalid input is re-asked\n'
test_guided_dns01_marks_the_credential_for_self_pasting "$(new_install_dir)"
printf 'PASS guided dns01 prepares the credential file and stops before setup.sh\n'
test_guided_loopback_archive_prepares_same_disk_storage "$(new_install_dir)"
printf 'PASS guided loopback archive prepares same-disk storage and reaches the stack\n'
test_version_skew_between_script_and_tree_warns "$(new_install_dir)"
printf 'PASS a tree whose install.sh differs from the running script is named\n'
