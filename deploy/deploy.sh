#!/bin/bash
#
# Power Manage - Build & Deploy Script
#
# Builds Go binaries, creates container images with podman, transfers them
# to the remote server, and restarts the services.
#
# Usage:
#   ./deploy.sh <ssh-host>                              # build + deploy all
#   ./deploy.sh <ssh-host> control gateway              # build + deploy specific services
#   ./deploy.sh -i ~/.ssh/mykey <ssh-host>              # use specific SSH key
#   ./deploy.sh --build-only                            # build images locally without deploying
#
# Examples:
#   ./deploy.sh user@pm.example.com
#   ./deploy.sh -i ~/.ssh/hetzner user@pm.example.com gateway
#   ./deploy.sh --build-only
#
# Prerequisites:
#   - Go 1.25+ installed locally
#   - Podman installed locally
#   - SSH access to the remote server
#   - Docker + Docker Compose on the remote server

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC}  $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step()  { echo -e "${BLUE}[STEP]${NC}  $1"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DIST_DIR="$PROJECT_ROOT/server/dist"

REGISTRY="ghcr.io/manchtools"
ALL_SERVICES=(control gateway indexer)

# Parse arguments
BUILD_ONLY=false
SSH_HOST=""
SSH_KEY=""
SERVICES=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --build-only)
            BUILD_ONLY=true
            shift
            ;;
        -i)
            SSH_KEY="$2"
            shift 2
            ;;
        -*)
            log_error "Unknown option: $1"
            exit 1
            ;;
        *)
            if [[ -z "$SSH_HOST" ]]; then
                SSH_HOST="$1"
            elif [[ " ${ALL_SERVICES[*]} " == *" $1 "* ]]; then
                SERVICES+=("$1")
            else
                log_error "Unknown service: $1 (valid: ${ALL_SERVICES[*]})"
                exit 1
            fi
            shift
            ;;
    esac
done

if ! $BUILD_ONLY && [[ -z "$SSH_HOST" ]]; then
    echo "Usage: $0 [-i ssh-key] <ssh-host> [service...]"
    echo "       $0 --build-only [service...]"
    echo ""
    echo "Options:"
    echo "  -i <key>    SSH private key file"
    echo ""
    echo "Services: ${ALL_SERVICES[*]} (default: all)"
    exit 1
fi

SSH_OPTS=()
if [[ -n "$SSH_KEY" ]]; then
    SSH_OPTS+=(-i "$SSH_KEY")
fi

# Remaining args are service names
for arg in "$@"; do
    if [[ " ${ALL_SERVICES[*]} " == *" $arg "* ]]; then
        SERVICES+=("$arg")
    else
        log_error "Unknown service: $arg (valid: ${ALL_SERVICES[*]})"
        exit 1
    fi
done

# Default to all services if none specified
if [[ ${#SERVICES[@]} -eq 0 ]]; then
    SERVICES=("${ALL_SERVICES[@]}")
fi

log_info "Services to build: ${SERVICES[*]}"

# Detect architecture
GOARCH="$(go env GOARCH 2>/dev/null || echo amd64)"
log_info "Target architecture: linux/$GOARCH"

###############################################################################
# Step 1: Build Go binaries
###############################################################################
log_step "Building Go binaries..."
mkdir -p "$DIST_DIR"

for svc in "${SERVICES[@]}"; do
    log_info "  Building $svc..."
    CGO_ENABLED=0 GOOS=linux GOARCH="$GOARCH" \
        go build -ldflags="-s -w" \
        -o "$DIST_DIR/$svc" \
        "$PROJECT_ROOT/server/cmd/$svc"
    log_info "  Built $DIST_DIR/$svc ($(du -h "$DIST_DIR/$svc" | cut -f1))"
done

###############################################################################
# Step 2: Build container images with podman
###############################################################################
log_step "Building container images..."

declare -A PORTS=([control]=8081 [gateway]=8080 [indexer]=8082)

for svc in "${SERVICES[@]}"; do
    IMAGE="$REGISTRY/power-manage-$svc:latest"
    PORT="${PORTS[$svc]}"

    log_info "  Building $IMAGE..."

    # Create a temporary Dockerfile matching the CI pattern
    TMPFILE=$(mktemp /tmp/Dockerfile.XXXXXX)
    cat > "$TMPFILE" <<EOF
FROM docker.io/library/alpine:3.21
RUN apk add --no-cache ca-certificates
COPY server/dist/$svc /usr/local/bin/$svc
RUN mkdir -p /certs && adduser -D -H appuser
USER appuser
EXPOSE $PORT
ENTRYPOINT ["/usr/local/bin/$svc"]
EOF

    podman build -f "$TMPFILE" -t "$IMAGE" "$PROJECT_ROOT"
    rm -f "$TMPFILE"

    log_info "  Built $IMAGE"
done

###############################################################################
# Step 3: Export images
###############################################################################
log_step "Exporting images..."

ARCHIVE_DIR=$(mktemp -d /tmp/pm-images.XXXXXX)

for svc in "${SERVICES[@]}"; do
    IMAGE="$REGISTRY/power-manage-$svc:latest"
    ARCHIVE="$ARCHIVE_DIR/pm-$svc.tar"

    log_info "  Saving $IMAGE..."
    podman save "$IMAGE" -o "$ARCHIVE"
    gzip "$ARCHIVE"
    log_info "  Saved $ARCHIVE.gz ($(du -h "$ARCHIVE.gz" | cut -f1))"
done

if $BUILD_ONLY; then
    log_info "Build complete. Images saved to:"
    for svc in "${SERVICES[@]}"; do
        echo "  $ARCHIVE_DIR/pm-$svc.tar.gz"
    done
    exit 0
fi

###############################################################################
# Step 4: Transfer to server
###############################################################################
log_step "Transferring images to $SSH_HOST..."

scp "${SSH_OPTS[@]}" "$ARCHIVE_DIR"/pm-*.tar.gz "$SSH_HOST:/tmp/"

# Also transfer setup.sh for certificate management
scp "${SSH_OPTS[@]}" "$SCRIPT_DIR/setup.sh" "$SSH_HOST:~/deploy/setup.sh"

log_info "Transfer complete"

###############################################################################
# Step 5: Load images and restart services on server
###############################################################################
log_step "Loading images and restarting services on $SSH_HOST..."

# Build the remote commands
# Read IMAGE_TAG from server's .env so we retag images to match what compose expects
REMOTE_CMDS="cd ~/deploy && "
REMOTE_CMDS+="IMAGE_TAG=\$(grep -oP '(?<=^IMAGE_TAG=).*' .env 2>/dev/null || echo latest) && "
REMOTE_CMDS+="echo '[INFO] Server IMAGE_TAG='\$IMAGE_TAG && "
for svc in "${SERVICES[@]}"; do
    REMOTE_CMDS+="echo '[INFO] Loading pm-$svc...' && "
    REMOTE_CMDS+="docker load < /tmp/pm-$svc.tar.gz && "
    REMOTE_CMDS+="rm -f /tmp/pm-$svc.tar.gz && "
    REMOTE_CMDS+="docker tag $REGISTRY/power-manage-$svc:latest $REGISTRY/power-manage-$svc:\$IMAGE_TAG && "
done
for svc in "${SERVICES[@]}"; do
    REMOTE_CMDS+="echo '[INFO] Restarting $svc...' && "
    REMOTE_CMDS+="docker compose up -d --no-deps --force-recreate $svc && "
done
REMOTE_CMDS+="echo '[INFO] All services restarted' && docker compose ps"

ssh "${SSH_OPTS[@]}" "$SSH_HOST" "$REMOTE_CMDS"

###############################################################################
# Cleanup
###############################################################################
rm -rf "$ARCHIVE_DIR"

echo ""
log_info "Deployment complete!"
echo ""

# Show service status
for svc in "${SERVICES[@]}"; do
    echo "  $svc  →  $REGISTRY/power-manage-$svc:latest"
done
echo ""
