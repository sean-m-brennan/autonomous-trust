#!/usr/bin/env bash
# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
# ******************
#
# Persistent local Docker registry for autonomous-trust images.
#
# Source this file from other scripts to get registry helper functions.
# The registry stores images on disk at REGISTRY_DISK so they survive
# Docker restarts and system reboots.
#
# Usage (standalone):
#   ./local-registry.sh start       # start the registry
#   ./local-registry.sh stop        # stop the registry
#   ./local-registry.sh status      # show registry status
#   ./local-registry.sh list        # list images in registry
#   ./local-registry.sh push IMAGE  # push a local image to registry
#
# Usage (sourced by other scripts):
#   source local-registry.sh
#   ensure_registry                  # start if not running
#   require_image "autonomous-trust-devel"  # pull or build

# ---------------------------------------------------------------------------
# Configuration (matches config/config.py)
# ---------------------------------------------------------------------------
REGISTRY_CONTAINER="at-registry"
REGISTRY_PORT="${REGISTRY_PORT:-5000}"
REGISTRY_HOST="localhost:${REGISTRY_PORT}"
REGISTRY_DISK="${REGISTRY_DISK:-$HOME/Software/.docker.dir}"
REGISTRY_IMAGE="registry:2"

_LOCAL_REG_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors (only set if not already defined)
: "${RED:=\033[0;31m}"
: "${GREEN:=\033[0;32m}"
: "${YELLOW:=\033[0;33m}"
: "${RESET:=\033[0m}"

_reg_info()  { echo -e "${GREEN}[registry]${RESET} $*"; }
_reg_warn()  { echo -e "${YELLOW}[registry]${RESET} $*"; }
_reg_error() { echo -e "${RED}[registry]${RESET} $*" >&2; }

# ---------------------------------------------------------------------------
# Registry lifecycle
# ---------------------------------------------------------------------------
registry_running() {
    docker inspect -f '{{.State.Running}}' "$REGISTRY_CONTAINER" 2>/dev/null | grep -q true
}

start_registry() {
    if registry_running; then
        _reg_info "Registry already running at $REGISTRY_HOST"
        return 0
    fi

    # Ensure storage directory exists
    mkdir -p "$REGISTRY_DISK"

    # Remove stopped container if it exists
    docker rm -f "$REGISTRY_CONTAINER" 2>/dev/null || true

    _reg_info "Starting local registry at $REGISTRY_HOST (storage: $REGISTRY_DISK) ..."
    docker run -d \
        --name "$REGISTRY_CONTAINER" \
        --restart unless-stopped \
        -p "${REGISTRY_PORT}:5000" \
        -v "${REGISTRY_DISK}:/var/lib/registry" \
        "$REGISTRY_IMAGE"

    # Wait for registry to be ready
    local retries=10
    while ! curl -sf "http://${REGISTRY_HOST}/v2/" >/dev/null 2>&1; do
        retries=$((retries - 1))
        if [[ $retries -le 0 ]]; then
            _reg_error "Registry failed to start"
            return 1
        fi
        sleep 1
    done
    _reg_info "Registry ready"
}

stop_registry() {
    if registry_running; then
        _reg_info "Stopping registry ..."
        docker stop "$REGISTRY_CONTAINER"
        _reg_info "Registry stopped (data preserved at $REGISTRY_DISK)"
    else
        _reg_info "Registry not running"
    fi
}

ensure_registry() {
    if ! registry_running; then
        start_registry
    fi
}

# ---------------------------------------------------------------------------
# Image operations
# ---------------------------------------------------------------------------
registry_has_image() {
    local image="$1"
    # Query the registry catalog and tags
    local name="${image%%:*}"
    local tag="${image#*:}"
    if [[ "$tag" == "$name" ]]; then
        tag="latest"
    fi
    curl -sf "http://${REGISTRY_HOST}/v2/${name}/tags/list" 2>/dev/null \
        | grep -q "\"${tag}\""
}

push_to_registry() {
    local image="$1"
    local name="${image%%:*}"
    local tag="${image#*:}"
    if [[ "$tag" == "$name" ]]; then
        tag="latest"
    fi
    local registry_ref="${REGISTRY_HOST}/${name}:${tag}"

    ensure_registry

    _reg_info "Pushing $image -> $registry_ref"
    docker tag "$image" "$registry_ref"
    docker push "$registry_ref"
    # Clean up the registry-prefixed tag (original tag stays)
    docker rmi "$registry_ref" 2>/dev/null || true
}

pull_from_registry() {
    local image="$1"
    local name="${image%%:*}"
    local tag="${image#*:}"
    if [[ "$tag" == "$name" ]]; then
        tag="latest"
    fi
    local registry_ref="${REGISTRY_HOST}/${name}:${tag}"

    _reg_info "Pulling $registry_ref -> $image"
    docker pull "$registry_ref"
    docker tag "$registry_ref" "$image"
    docker rmi "$registry_ref" 2>/dev/null || true
}

list_registry() {
    ensure_registry
    local catalog
    catalog=$(curl -sf "http://${REGISTRY_HOST}/v2/_catalog" 2>/dev/null)
    if [[ -z "$catalog" ]]; then
        _reg_info "Registry is empty"
        return
    fi

    _reg_info "Images in registry ($REGISTRY_HOST):"
    echo "$catalog" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for repo in sorted(data.get('repositories', [])):
    print('  ' + repo)
" 2>/dev/null || echo "$catalog"
}

# ---------------------------------------------------------------------------
# The main helper: pull from registry, or build + push as fallback
# ---------------------------------------------------------------------------
require_image() {
    local image="$1"
    shift
    # Remaining args are passed to build-docker.sh if build is needed
    local build_targets=("$@")

    # 1. Already available locally?
    if docker image inspect "$image" >/dev/null 2>&1; then
        _reg_info "$image available locally"
        return 0
    fi

    # 2. Available in local registry?
    ensure_registry
    if registry_has_image "$image"; then
        pull_from_registry "$image"
        return 0
    fi

    # 3. Build it
    _reg_warn "$image not found locally or in registry — building ..."
    if [[ ${#build_targets[@]} -gt 0 ]]; then
        "$_LOCAL_REG_SCRIPT_DIR/build-docker.sh" "${build_targets[@]}"
    else
        # Infer build target from image name
        local target
        target="${image#autonomous-trust-}"  # e.g., "devel" from "autonomous-trust-devel"
        if [[ "$target" == "$image" ]]; then
            # No suffix — it's the base "autonomous-trust" image
            target="release"
        fi
        "$_LOCAL_REG_SCRIPT_DIR/build-docker.sh" "$target"
    fi

    # 4. Push to registry for next time
    if docker image inspect "$image" >/dev/null 2>&1; then
        push_to_registry "$image"
    else
        _reg_error "Build did not produce image: $image"
        return 1
    fi
}

# ---------------------------------------------------------------------------
# Standalone CLI
# ---------------------------------------------------------------------------
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    case "${1:-help}" in
        start)  start_registry ;;
        stop)   stop_registry ;;
        status)
            if registry_running; then
                _reg_info "Registry is running at $REGISTRY_HOST (storage: $REGISTRY_DISK)"
            else
                _reg_info "Registry is not running"
            fi
            ;;
        list)   list_registry ;;
        push)
            if [[ -z "${2:-}" ]]; then
                _reg_error "Usage: $0 push IMAGE"
                exit 1
            fi
            push_to_registry "$2"
            ;;
        help|--help|-h)
            echo "Usage: $0 {start|stop|status|list|push IMAGE}"
            echo
            echo "Persistent local Docker registry for autonomous-trust images."
            echo "Storage: $REGISTRY_DISK"
            echo "Address: $REGISTRY_HOST"
            ;;
        *)
            _reg_error "Unknown command: $1"
            echo "Usage: $0 {start|stop|status|list|push IMAGE}"
            exit 1
            ;;
    esac
fi
