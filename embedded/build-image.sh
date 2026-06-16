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
# Build a hardened, minimal SD card image for Raspberry Pi 4 / CM4.
#
# This script:
#   1. Builds a fully static at_demo binary (via build-arm.sh --static)
#   2. Signs the binary with Ed25519
#   3. Runs Buildroot to produce a minimal Linux image with dm-verity
#   4. Outputs: embedded/dist/autonomous-trust.img
#
# Prerequisites:
#   - Docker with buildx
#   - ~10GB disk space for Buildroot build cache
#
# Usage:
#   ./build-image.sh                    # full build
#   ./build-image.sh --skip-binary      # reuse existing static binary
#   ./build-image.sh --sign             # sign binary (requires signing key)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DIST_DIR="$SCRIPT_DIR/dist"
BR_DIR="$SCRIPT_DIR/buildroot"
BR_BUILD_DIR="$SCRIPT_DIR/.buildroot-build"
BR_VERSION="2024.02.10"

SKIP_BINARY=false
SIGN=false
FORCE=false

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
RESET='\033[0m'

info()  { echo -e "${GREEN}[build-image]${RESET} $*"; }
warn()  { echo -e "${YELLOW}[build-image]${RESET} $*"; }
error() { echo -e "${RED}[build-image]${RESET} $*" >&2; }
step()  { echo -e "${CYAN}[build-image]${RESET} === $* ==="; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-binary) SKIP_BINARY=true; shift ;;
        --sign)        SIGN=true; shift ;;
        --force)       FORCE=true; shift ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo
            echo "Options:"
            echo "  --skip-binary    Reuse existing static binary in dist/"
            echo "  --sign           Sign binary with Ed25519 key"
            echo "  --force          Rebuild everything from scratch"
            exit 0 ;;
        *) error "Unknown option: $1"; exit 1 ;;
    esac
done

# Check disk space
AVAIL_GB=$(df -BG "$SCRIPT_DIR" | tail -1 | awk '{print $4}' | tr -d 'G')
if [ "$AVAIL_GB" -lt 5 ]; then
    error "Less than 5GB available. Buildroot needs ~10GB. Aborting."
    exit 1
fi

# -----------------------------------------------------------------------
# Step 1: Build static binary
# -----------------------------------------------------------------------
step "Static binary"

STATIC_TARBALL="$DIST_DIR/autonomous-trust-arm64-static.tar.gz"
STATIC_BINARY="$DIST_DIR/at_demo-arm64-static"

if $SKIP_BINARY && [ -f "$STATIC_BINARY" ]; then
    info "Reusing existing static binary: $STATIC_BINARY"
else
    info "Building static arm64 binary ..."
    FORCE_FLAG=""
    if $FORCE; then FORCE_FLAG="--force"; fi
    "$SCRIPT_DIR/build-arm.sh" --static $FORCE_FLAG

    # Extract the binary from the tarball
    info "Extracting binary from tarball ..."
    mkdir -p "$DIST_DIR/staging-static"
    tar -xzf "$STATIC_TARBALL" -C "$DIST_DIR/staging-static"
    # build-arm.sh stages the static binary uniformly under
    # opt/autonomous-trust/bin/ (not the in-container /usr/local/bin path).
    cp "$DIST_DIR/staging-static/opt/autonomous-trust/bin/at_demo" "$STATIC_BINARY"
    rm -rf "$DIST_DIR/staging-static"
fi

info "Static binary: $(ls -lh "$STATIC_BINARY" | awk '{print $5}')"

# -----------------------------------------------------------------------
# Step 2: Sign binary (optional)
# -----------------------------------------------------------------------
if $SIGN; then
    step "Binary signing"
    if [ ! -f "$SCRIPT_DIR/signing.key" ]; then
        info "No signing key found. Generating ..."
        "$SCRIPT_DIR/sign-binary.sh" --binary "$STATIC_BINARY" --generate-key
    else
        "$SCRIPT_DIR/sign-binary.sh" --binary "$STATIC_BINARY" --key "$SCRIPT_DIR/signing.key"
    fi
fi

# -----------------------------------------------------------------------
# Step 3: Prepare Buildroot Docker image and overlay
# -----------------------------------------------------------------------
step "Buildroot setup"

BR_DOCKER_IMAGE="at-buildroot"
BR_DOCKERFILE="$BR_DIR/Dockerfile"

# Build the Buildroot Docker image (caches Buildroot download + host deps)
if $FORCE || ! docker image inspect "$BR_DOCKER_IMAGE" &>/dev/null; then
    info "Building Buildroot Docker image ..."
    local_args=()
    if $FORCE; then local_args+=(--no-cache); fi
    docker build "${local_args[@]}" \
        --build-arg "BR_VERSION=$BR_VERSION" \
        -t "$BR_DOCKER_IMAGE" \
        -f "$BR_DOCKERFILE" \
        "$BR_DIR"
fi

# Inject static binary into rootfs overlay
OVERLAY_BIN="$BR_DIR/rootfs-overlay/usr/local/bin"
mkdir -p "$OVERLAY_BIN"
cp "$STATIC_BINARY" "$OVERLAY_BIN/at_demo"
chmod 755 "$OVERLAY_BIN/at_demo"

# Copy signature if it exists
if [ -f "${STATIC_BINARY}.sig" ]; then
    cp "${STATIC_BINARY}.sig" "$OVERLAY_BIN/at_demo.sig"
fi

# -----------------------------------------------------------------------
# Step 4: Run Buildroot inside Docker
# -----------------------------------------------------------------------
step "Buildroot build (in Docker)"

# Persistent directories for Buildroot build cache and downloads
mkdir -p "$BR_BUILD_DIR/output" "$BR_BUILD_DIR/dl"

# Inside the container:
#   /buildroot     = Buildroot source (baked into image)
#   /work          = mounted embedded/buildroot/ (configs, overlay, scripts)
#   /output        = mounted build cache + output images
#   /buildroot/dl  = mounted download cache (persists source tarballs)
#
# BR2_EXTERNAL_AT_PATH points to /work so the defconfig can reference
# $(BR2_EXTERNAL_AT_PATH)/rootfs-overlay, post-build.sh, etc.
#
# Both defconfig and build run in a single container so they share state.

info "Loading defconfig and building ..."
docker run --rm \
    --network host \
    -v "$BR_DIR:/work" \
    -v "$BR_BUILD_DIR/output:/output" \
    -v "$BR_BUILD_DIR/dl:/buildroot/dl" \
    "$BR_DOCKER_IMAGE" \
    "apt-get update -qq && apt-get install -y -qq libssl-dev mtools >/dev/null 2>&1; \
     cd /buildroot && \
     make O=/output BR2_EXTERNAL_AT_PATH=/work BR2_DEFCONFIG=/work/at_defconfig defconfig && \
     make O=/output BR2_EXTERNAL_AT_PATH=/work -j\$(nproc)"

# -----------------------------------------------------------------------
# Step 5: Collect output
# -----------------------------------------------------------------------
step "Collecting output"

BUILD_OUTPUT="$BR_BUILD_DIR/output"
FINAL_IMG="$DIST_DIR/autonomous-trust.img"
if [ -f "$BUILD_OUTPUT/images/autonomous-trust.img" ]; then
    cp "$BUILD_OUTPUT/images/autonomous-trust.img" "$FINAL_IMG"
    info "SD card image: $FINAL_IMG ($(du -h "$FINAL_IMG" | cut -f1))"
else
    warn "No assembled .img found; check post-image.sh output"
    info "Individual images in: $BUILD_OUTPUT/images/"
    ls -lh "$BUILD_OUTPUT/images/" 2>/dev/null || info "(no images directory yet)"
fi

if [ -f "$BUILD_OUTPUT/images/root-hash.txt" ]; then
    ROOT_HASH=$(cat "$BUILD_OUTPUT/images/root-hash.txt")
    info "dm-verity root hash: $ROOT_HASH"
    cp "$BUILD_OUTPUT/images/root-hash.txt" "$DIST_DIR/"
fi

info ""
info "Flash to SD card with:"
info "  sudo ./flash.sh $FINAL_IMG /dev/sdX"
