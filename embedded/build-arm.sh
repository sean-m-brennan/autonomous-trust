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
# Cross-compile at_demo for ARM64 (and optionally AMD64) via docker buildx.
# Produces architecture-specific tarballs in dist/.
#
# Usage:
#   ./build-arm.sh                  # build arm64 only
#   ./build-arm.sh --all-arch       # build arm64 + amd64
#   ./build-arm.sh --force          # rebuild from scratch (--no-cache)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DIST_DIR="$SCRIPT_DIR/dist"
DOCKERFILE="$REPO_DIR/src/autonomous-trust/Dockerfile-c"
IMAGE_BASE="autonomous-trust-c"

FORCE=false
ALL_ARCH=false
PLATFORMS=(linux/arm64)

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RESET='\033[0m'

info()  { echo -e "${GREEN}[build-arm]${RESET} $*"; }
warn()  { echo -e "${YELLOW}[build-arm]${RESET} $*"; }
error() { echo -e "${RED}[build-arm]${RESET} $*" >&2; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --force)     FORCE=true; shift ;;
        --all-arch)  ALL_ARCH=true; shift ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo
            echo "Options:"
            echo "  --all-arch   Build for both arm64 and amd64"
            echo "  --force      Rebuild from scratch (--no-cache)"
            echo "  -h, --help   Show this help"
            exit 0 ;;
        *) error "Unknown option: $1"; exit 1 ;;
    esac
done

if $ALL_ARCH; then
    PLATFORMS=(linux/arm64 linux/amd64)
fi

# Preflight
if ! command -v docker &>/dev/null; then
    error "Docker is required but not found"
    exit 1
fi

# Ensure buildx builder exists with multi-platform support
BUILDER_NAME="at-multiarch"
if ! docker buildx inspect "$BUILDER_NAME" &>/dev/null; then
    info "Creating buildx builder '$BUILDER_NAME' ..."
    docker buildx create --name "$BUILDER_NAME" --use --bootstrap
else
    docker buildx use "$BUILDER_NAME"
fi

GIT_VERSION="$(git -C "$REPO_DIR" describe --tags --always --dirty 2>/dev/null || echo "unknown")"
mkdir -p "$DIST_DIR"

extract_artifacts() {
    local platform="$1"
    local arch="${platform#linux/}"  # arm64 or amd64
    local container_name="at-extract-${arch}-$$"
    local tarball="$DIST_DIR/autonomous-trust-${arch}.tar.gz"

    info "Building for $platform ..."

    local build_args=(
        --platform "$platform"
        --build-arg "GIT_VERSION=$GIT_VERSION"
        --load
        -t "${IMAGE_BASE}:${arch}"
        -f "$DOCKERFILE"
    )
    if $FORCE; then
        build_args+=(--no-cache)
    fi
    build_args+=("$REPO_DIR")

    docker buildx build "${build_args[@]}"

    info "Extracting artifacts for $arch ..."
    docker create --name "$container_name" --platform "$platform" "${IMAGE_BASE}:${arch}" /bin/true
    trap "docker rm -f '$container_name' 2>/dev/null || true" EXIT

    local staging="$DIST_DIR/staging-${arch}"
    rm -rf "$staging"
    mkdir -p "$staging/usr/local/bin" "$staging/usr/local/lib"

    docker cp "$container_name:/usr/local/bin/at_demo" "$staging/usr/local/bin/"
    docker cp "$container_name:/usr/local/lib/libautonomous_trust.so" "$staging/usr/local/lib/"
    docker rm -f "$container_name"
    trap - EXIT

    tar -czf "$tarball" -C "$staging" .
    rm -rf "$staging"

    info "Created $tarball"
    echo "  $(file "$staging/../$(basename "$tarball")" 2>/dev/null || echo "$tarball")"
}

for platform in "${PLATFORMS[@]}"; do
    extract_artifacts "$platform"
done

info "Build artifacts in $DIST_DIR:"
ls -lh "$DIST_DIR"/*.tar.gz
