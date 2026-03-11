#!/usr/bin/env bash
# ******************
#  Copyright 2025 Sean M. Brennan and contributors
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
# Docker image builder for autonomous-trust.
#
# Builds one or more container images used by the project.
#
# Usage:
#   ./build-docker.sh                    # build devel + test (default)
#   ./build-docker.sh devel              # build only the devel image
#   ./build-docker.sh test               # build only the test image
#   ./build-docker.sh full-devel         # build devel + full-devel
#   ./build-docker.sh builder            # build the conda package builder
#   ./build-docker.sh release            # build the pre-built release image
#   ./build-docker.sh full               # build the full release image
#   ./build-docker.sh lite               # build the lightweight image
#   ./build-docker.sh all                # build everything
#   ./build-docker.sh --force devel test # rebuild from scratch

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$SCRIPT_DIR/src"
AT_DIR="$SRC_DIR/autonomous-trust"

# Defaults (from config/config.py)
IMAGE_NAME="autonomous-trust"

FORCE=false
DEBUG=false
REGISTRY_URL=""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RESET='\033[0m'

info()  { echo -e "${GREEN}[docker]${RESET} $*"; }
warn()  { echo -e "${YELLOW}[docker]${RESET} $*"; }
error() { echo -e "${RED}[docker]${RESET} $*" >&2; }

# ---------------------------------------------------------------------------
# Parse flags (before positional targets)
# ---------------------------------------------------------------------------
TARGETS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --force)      FORCE=true; shift ;;
        --debug)      DEBUG=true; shift ;;
        --registry)   REGISTRY_URL="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS] [TARGETS...]"
            echo
            echo "Targets (default: devel test):"
            echo "  devel        Development image (live sources)"
            echo "  test         Test runner image (depends on devel)"
            echo "  full-devel   Full development image with all subpackages"
            echo "  builder      Conda package builder image"
            echo "  release      Pre-built release image"
            echo "  full         Full release image with all subpackages"
            echo "  lite         Lightweight image (no conda)"
            echo "  all          Build all images"
            echo
            echo "Options:"
            echo "  --force          Rebuild from scratch (--no-cache)"
            echo "  --debug          Verbose build output (--progress=plain)"
            echo "  --registry URL   Docker registry URL prefix"
            exit 0 ;;
        -*) error "Unknown option: $1"; exit 1 ;;
        *)  TARGETS+=("$1"); shift ;;
    esac
done

# Default targets
if [ ${#TARGETS[@]} -eq 0 ]; then
    TARGETS=(devel test)
fi

# Expand "all"
if [[ " ${TARGETS[*]} " == *" all "* ]]; then
    TARGETS=(builder devel test full-devel release full lite)
fi

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
if ! command -v docker &>/dev/null; then
    error "Docker is required but not found"
    exit 1
fi

# Source local registry helpers (push after build)
source "$SCRIPT_DIR/local-registry.sh" 2>/dev/null || true

# ---------------------------------------------------------------------------
# Common build args
# ---------------------------------------------------------------------------
common_build_args() {
    local args=()
    if $FORCE; then
        args+=(--no-cache)
    fi
    if $DEBUG; then
        args+=(--progress=plain)
    fi
    if [[ -n "$REGISTRY_URL" ]]; then
        args+=(--build-arg "REGISTRY_URL=$REGISTRY_URL")
    fi
    echo "${args[@]}"
}

# ---------------------------------------------------------------------------
# Individual build functions
# ---------------------------------------------------------------------------
build_devel() {
    info "Building ${IMAGE_NAME}-devel ..."
    local args
    read -ra args <<< "$(common_build_args)"
    docker build "${args[@]}" \
        -t "${IMAGE_NAME}-devel" \
        -f "$AT_DIR/Dockerfile-devel" \
        "$SCRIPT_DIR"
    push_to_registry "${IMAGE_NAME}-devel" 2>/dev/null || true
}

build_test() {
    info "Building ${IMAGE_NAME}-test ..."
    local args
    read -ra args <<< "$(common_build_args)"
    docker build "${args[@]}" \
        -t "${IMAGE_NAME}-test" \
        -f "$AT_DIR/Dockerfile-test" \
        "$AT_DIR"
    push_to_registry "${IMAGE_NAME}-test" 2>/dev/null || true
}

build_full_devel() {
    info "Building ${IMAGE_NAME}-full-devel ..."
    local args
    read -ra args <<< "$(common_build_args)"
    docker build "${args[@]}" \
        -t "${IMAGE_NAME}-full-devel" \
        -f "$SRC_DIR/Dockerfile-devel" \
        "$SCRIPT_DIR"
    push_to_registry "${IMAGE_NAME}-full-devel" 2>/dev/null || true
}

build_builder() {
    info "Building package-builder ..."
    local args
    read -ra args <<< "$(common_build_args)"
    docker build "${args[@]}" \
        -t "package-builder" \
        -f "$SRC_DIR/Dockerfile-build" \
        "$SRC_DIR"
    push_to_registry "package-builder" 2>/dev/null || true
}

build_release() {
    info "Building ${IMAGE_NAME} (release) ..."
    local args
    read -ra args <<< "$(common_build_args)"
    docker build "${args[@]}" \
        -t "${IMAGE_NAME}" \
        -f "$AT_DIR/Dockerfile" \
        "$SRC_DIR"
    push_to_registry "${IMAGE_NAME}" 2>/dev/null || true
}

build_full() {
    info "Building ${IMAGE_NAME}-full ..."
    local args
    read -ra args <<< "$(common_build_args)"
    docker build "${args[@]}" \
        -t "${IMAGE_NAME}-full" \
        -f "$SRC_DIR/Dockerfile" \
        "$SRC_DIR"
    push_to_registry "${IMAGE_NAME}-full" 2>/dev/null || true
}

build_lite() {
    info "Building ${IMAGE_NAME}-lite ..."
    local args
    read -ra args <<< "$(common_build_args)"
    docker build "${args[@]}" \
        -t "${IMAGE_NAME}-lite" \
        -f "$AT_DIR/Dockerfile-lite" \
        "$SCRIPT_DIR"
    push_to_registry "${IMAGE_NAME}-lite" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    info "Building Docker images: ${TARGETS[*]}"
    echo

    for target in "${TARGETS[@]}"; do
        case "$target" in
            devel)      build_devel ;;
            test)       build_test ;;
            full-devel) build_full_devel ;;
            builder)    build_builder ;;
            release)    build_release ;;
            full)       build_full ;;
            lite)       build_lite ;;
            *)          error "Unknown target: $target"; exit 1 ;;
        esac
        echo
    done

    info "Done"
}

main
