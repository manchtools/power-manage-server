#!/usr/bin/env bash
#
# Power Manage Server bootstrap installer.
#
#   curl -fsSL https://raw.githubusercontent.com/MANCHTOOLS/power-manage-server/main/deploy/install.sh | sudo bash
#
# Pulls the deploy/ tree from a chosen release tag, runs setup.sh
# (interactive guided mode by default), pulls images, brings the
# stack up. Does NOT install Docker — checks for it and fails with a
# clear message if missing. Operator owns Docker setup via their
# preferred channel (apt / dnf / official convenience script).
#
# Idempotent: re-running on an existing install does not clobber
# .env or regenerate certs; offers to update IMAGE_TAG and restart.
#
# Env-var overrides:
#   INSTALL_DIR    Target directory (default: /opt/power-manage)
#   RELEASE_TAG    Image + deploy tag (default: latest-rc)
#   NO_PROMPT      Set to 1 to skip the guided setup loop
#
# rc11 #80.

set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-/opt/power-manage}"
RELEASE_TAG="${RELEASE_TAG:-latest-rc}"
NO_PROMPT="${NO_PROMPT:-0}"
GITHUB_REPO="manchtools/power-manage-server"

# Holds the mktemp -d path used by download_deploy_tree so the EXIT
# trap can clean it up. Declared at script scope (not `local` inside
# the function) because `set -u` + a function-local trap reference
# expands an out-of-scope name once the function returns, exploding
# the trap with "tmpdir: unbound variable" — the rc1 install bug.
PM_INSTALL_TMPDIR=""
trap 'rm -rf "${PM_INSTALL_TMPDIR:-}"' EXIT

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }

# resolve_release_tag turns the floating-tag aliases :latest-rc and
# :latest (the container-image contract names) into the actual git
# tag they point at, by hitting the GitHub Releases API. The previous
# code path treated them as git refs directly and failed with
# "Could not resolve as tag or branch" because no such ref exists.
#
# An explicit tag (vYYYY.MM[-rcN]) is left untouched.
resolve_release_tag() {
    case "$RELEASE_TAG" in
        latest-rc)
            local api_url="https://api.github.com/repos/${GITHUB_REPO}/releases?per_page=30"
            local resolved
            resolved="$(curl -fsSL "$api_url" | _first_prerelease_tag)" || true
            ;;
        latest)
            local api_url="https://api.github.com/repos/${GITHUB_REPO}/releases/latest"
            local resolved
            resolved="$(curl -fsSL "$api_url" | _release_tag_name)" || true
            ;;
        *)
            return 0
            ;;
    esac
    if [[ -z "${resolved:-}" || "$resolved" == "null" ]]; then
        log_error "Could not resolve $RELEASE_TAG via the GitHub releases API on $GITHUB_REPO."
        log_error "  Pass an explicit tag instead, e.g.: RELEASE_TAG=v2026.06-rc1 ./install.sh"
        exit 1
    fi
    log_info "  Resolved $RELEASE_TAG → $resolved"
    RELEASE_TAG="$resolved"
}

# JSON parsing helpers — python3 is the primary path (preinstalled on
# every supported distro); jq is the fallback if the operator has
# stripped python; failure mode is a clear "install one or pass an
# explicit RELEASE_TAG" rather than a silent empty resolve.
_first_prerelease_tag() {
    if command -v python3 >/dev/null 2>&1; then
        python3 -c 'import json,sys
data=json.load(sys.stdin)
for r in data:
    if r.get("prerelease") and not r.get("draft"):
        print(r["tag_name"]); break'
    elif command -v jq >/dev/null 2>&1; then
        jq -r 'map(select(.prerelease==true and .draft==false))[0].tag_name'
    else
        log_error "Neither python3 nor jq is installed; cannot parse the GitHub releases API."
        log_error "  Install one, or set an explicit RELEASE_TAG (e.g. v2026.06-rc1)."
        exit 1
    fi
}

_release_tag_name() {
    if command -v python3 >/dev/null 2>&1; then
        python3 -c 'import json,sys; print(json.load(sys.stdin).get("tag_name",""))'
    elif command -v jq >/dev/null 2>&1; then
        jq -r '.tag_name // empty'
    else
        log_error "Neither python3 nor jq is installed; cannot parse the GitHub releases API."
        exit 1
    fi
}

###############################################################################
# Step 1 — preflight
#
# We DO NOT install Docker. Too many distro/version permutations to
# do safely from a generic installer; operators handle that via the
# official Docker convenience script or their package manager. We
# just check that both pieces are present and runnable as the
# current user.
###############################################################################
preflight() {
    log_info "Preflight checks…"

    if ! command -v docker >/dev/null 2>&1; then
        log_error "docker not found. Install Docker first via your distro's package manager"
        log_error "  or the official convenience script: https://docs.docker.com/engine/install/"
        exit 1
    fi

    if ! docker compose version >/dev/null 2>&1; then
        log_error "docker compose plugin not found. Install via:"
        log_error "  Debian/Ubuntu:  sudo apt install docker-compose-plugin"
        log_error "  Fedora:         sudo dnf install docker-compose-plugin"
        log_error "  Or per-distro instructions: https://docs.docker.com/compose/install/"
        exit 1
    fi

    if ! docker info >/dev/null 2>&1; then
        log_error "docker daemon not reachable. Either start it (sudo systemctl start docker)"
        log_error "  or run install.sh as a user in the docker group / as root."
        exit 1
    fi

    if ! command -v curl >/dev/null 2>&1; then
        log_error "curl not found — required for downloading the release tarball."
        exit 1
    fi

    if ! command -v tar >/dev/null 2>&1; then
        log_error "tar not found — required for extracting the release tarball."
        exit 1
    fi

    log_info "  docker:         $(docker --version | cut -d, -f1)"
    log_info "  docker compose: $(docker compose version --short 2>/dev/null || echo unknown)"
    log_info "  install dir:    $INSTALL_DIR"
    log_info "  release tag:    $RELEASE_TAG"
}

###############################################################################
# Step 2 — fetch the deploy/ tree
#
# Downloads the release tarball from GitHub and extracts only the
# server/deploy/ subdirectory into INSTALL_DIR. Avoids needing git
# on the host for what is fundamentally a deploy-artifact pull.
#
# RELEASE_TAG can be a specific tag (v2026.05-rc11) OR a curated
# floating tag (latest-rc, main). We resolve via the GitHub
# tarball-download endpoint which accepts both.
###############################################################################
download_deploy_tree() {
    # Map :latest / :latest-rc to a real git tag before trying to
    # download the source tarball.
    resolve_release_tag

    log_info "Fetching deploy tree from $GITHUB_REPO@$RELEASE_TAG…"

    # Use the script-scope var so the EXIT trap at the top of the
    # script can clean it up without referencing an out-of-scope
    # local. See PM_INSTALL_TMPDIR declaration up top.
    PM_INSTALL_TMPDIR="$(mktemp -d)"
    local tmpdir="$PM_INSTALL_TMPDIR"

    local tarball="$tmpdir/source.tar.gz"

    # GitHub serves tarballs at /{owner}/{repo}/archive/refs/{heads,tags}/{ref}.tar.gz.
    # We try tags first (release case), then heads (branch case for "main").
    local url_tag="https://github.com/${GITHUB_REPO}/archive/refs/tags/${RELEASE_TAG}.tar.gz"
    local url_branch="https://github.com/${GITHUB_REPO}/archive/refs/heads/${RELEASE_TAG}.tar.gz"

    if curl -fsSL "$url_tag" -o "$tarball" 2>/dev/null; then
        log_info "  Resolved as tag: $RELEASE_TAG"
    elif curl -fsSL "$url_branch" -o "$tarball" 2>/dev/null; then
        log_info "  Resolved as branch: $RELEASE_TAG"
    else
        log_error "Could not resolve $RELEASE_TAG as either a tag or branch on $GITHUB_REPO."
        log_error "  Check the spelling, or set RELEASE_TAG to a known value:"
        log_error "    RELEASE_TAG=latest-rc  ./install.sh   # latest pre-release (curated)"
        log_error "    RELEASE_TAG=v2026.05   ./install.sh   # specific stable release"
        exit 1
    fi

    # Extract only the deploy/ subtree. The tarball top-level
    # directory is repo-{tag}, so we strip the first component AND
    # restrict to deploy/* paths.
    mkdir -p "$INSTALL_DIR"

    if [[ -f "$INSTALL_DIR/.env" ]]; then
        log_warn "Existing .env found at $INSTALL_DIR/.env — preserving it (idempotent re-run)."
        # Stash it so the extract can overwrite docker-compose.yml /
        # setup.sh / etc. without clobbering the operator's secrets.
        cp "$INSTALL_DIR/.env" "$tmpdir/.env.preserved"
    fi

    # --strip-components=2 turns "repo-tag/deploy/file" into "file".
    # The "*/deploy" wildcard restricts extraction to just the
    # deploy/ subtree.
    tar -xzf "$tarball" \
        -C "$INSTALL_DIR" \
        --strip-components=2 \
        --wildcards \
        '*/deploy/*'

    # tar exits 0 even when the wildcard matches nothing — e.g. a
    # future tag that renames deploy/ or a private fork with a
    # different layout. Fail loudly here instead of letting the
    # operator chase a confusing "setup.sh: command not found" later.
    if [[ ! -f "$INSTALL_DIR/setup.sh" ]] || [[ ! -f "$INSTALL_DIR/.env.example" ]]; then
        log_error "Extracted tarball but expected files (setup.sh / .env.example) are missing under $INSTALL_DIR."
        log_error "  The tarball at $RELEASE_TAG may not contain a deploy/ subtree in the expected layout."
        exit 1
    fi

    if [[ -f "$tmpdir/.env.preserved" ]]; then
        cp "$tmpdir/.env.preserved" "$INSTALL_DIR/.env"
        log_info "  Preserved .env restored."
    fi

    log_info "  Extracted to $INSTALL_DIR/"
}

###############################################################################
# Step 3 — initialise .env if missing
###############################################################################
init_env() {
    cd "$INSTALL_DIR"
    if [[ ! -f .env ]]; then
        cp .env.example .env
        log_info "Created .env from .env.example — guided setup will fill it in."
    else
        log_info ".env already exists — guided setup will only prompt for missing values."
    fi
}

###############################################################################
# Step 4 — run setup.sh (cert generation + guided env loop)
###############################################################################
run_setup() {
    cd "$INSTALL_DIR"
    if [[ ! -x ./setup.sh ]]; then
        chmod +x ./setup.sh
    fi

    if [[ "$NO_PROMPT" == "1" ]]; then
        ./setup.sh --no-prompt
    elif [[ -r /dev/tty ]]; then
        # When this installer was piped (the documented
        # `curl … | sudo bash` flow), our stdin is the pipe and
        # setup.sh's `-t 0` check would auto-fall-back to
        # non-interactive mode — which then fails immediately on the
        # CHANGE_ME placeholders in a fresh .env. Reattach to the
        # controlling terminal so the prompt loop actually runs.
        # If /dev/tty is unreadable (true non-interactive context like
        # CI without NO_PROMPT=1), the existing -t 0 fallback in
        # setup.sh still produces a clean "validate .env directly"
        # path with the right error.
        ./setup.sh </dev/tty
    else
        ./setup.sh
    fi
}

###############################################################################
# Step 5 — pull images and start
###############################################################################
start_stack() {
    cd "$INSTALL_DIR"

    # Defense-in-depth against the dockerd bind-mount footgun:
    # compose.yml mounts ./valkey.conf into pm-valkey, and if the
    # host path doesn't exist when compose runs, dockerd silently
    # creates it as a DIRECTORY. Valkey then loads with no config,
    # `requirepass` is unset, and every downstream auth fails with
    # "AUTH called without any password configured". setup.sh
    # render_valkey_config writes the real file, but if it failed
    # or was skipped, surface that here rather than letting docker
    # paper over it.
    if [[ -d valkey.conf ]]; then
        log_error "valkey.conf exists as a directory — docker auto-created the bind-mount source on a prior partial run."
        log_error "  Remove it and re-run setup.sh: rm -rf valkey.conf && ./setup.sh --no-prompt"
        exit 1
    fi
    if [[ ! -f valkey.conf ]]; then
        log_error "valkey.conf is missing — setup.sh did not render it."
        log_error "  Run: ./setup.sh   (or ./setup.sh --no-prompt for non-interactive mode)"
        exit 1
    fi

    log_info "Pulling images…"
    docker compose pull

    log_info "Bringing up the stack…"
    docker compose up -d

    log_info "Waiting for services to settle…"
    sleep 8
    docker compose ps
}

###############################################################################
# Step 6 — post-install summary
###############################################################################
print_summary() {
    cd "$INSTALL_DIR"

    # Re-source .env so we can echo the final URLs back to the operator.
    # `set -u` is on (set -euo pipefail at the top); .env values that
    # accidentally reference an undefined var (typo'd $FOO) would abort
    # the script here, swallowing the install-success message. Relax
    # nounset just for the source call.
    set +u
    set -a
    # shellcheck disable=SC1091
    source ./.env
    set +a
    set -u

    echo ""
    log_info "✓ Power Manage Server is up."
    echo ""
    echo "  Control UI:    https://${CONTROL_DOMAIN:-<unset>}"
    echo "  Gateway mTLS:  https://${GATEWAY_DOMAIN:-<unset>}"
    if [[ -n "${GATEWAY_TTY_DOMAIN:-}" ]]; then
        echo "  TTY traffic:   https://${GATEWAY_TTY_DOMAIN}"
    fi
    echo ""
    echo "  Admin login:   ${ADMIN_EMAIL:-<unset>}"
    echo "  Install dir:   $INSTALL_DIR"
    echo ""
    echo "Next steps:"
    echo "  1. Wait ~30s for Let's Encrypt to issue certs (first run only)."
    echo "  2. Log in to the Control UI and create real user accounts."
    echo "  3. Generate a registration token, then enroll an agent on a device:"
    echo "       curl -fsSL https://github.com/MANCHTOOLS/power-manage-agent/releases/latest/download/install.sh | sudo bash -s -- -s https://${CONTROL_DOMAIN:-<DOMAIN>} -t <TOKEN>"
    echo ""
    echo "  Logs:          docker compose -f $INSTALL_DIR/compose.yml logs -f"
    echo ""
}

main() {
    log_info "Power Manage Server installer (rc11)"
    echo ""

    preflight
    download_deploy_tree
    init_env
    run_setup
    start_stack
    print_summary
}

main "$@"
