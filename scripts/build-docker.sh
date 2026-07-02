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
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SRC_DIR="$REPO_DIR/src"
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
        "$REPO_DIR"
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
        "$REPO_DIR"
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

# Run the package-builder image against each source package that has a
# meta.yaml, producing conda artifacts under src/dist/conda-repo. The
# Dockerfile's WORKDIR is /build and its CMD builds `.` — so we override
# the working directory to /build/src (where the recipe is mounted). The
# release/full/lite Docker images bind-mount the output of this step at
# /app/dist during their builds.
run_builder() {
    local conda_repo="$SRC_DIR/dist/conda-repo"
    if $FORCE && [[ -d "$conda_repo" ]]; then
        info "--force: wiping $conda_repo"
        rm -rf "$conda_repo"
    fi
    if [[ -d "$conda_repo" ]] && [[ -n "$(ls -A "$conda_repo" 2>/dev/null)" ]]; then
        info "package-builder output exists at $conda_repo (skip); pass --force to rebuild"
        return 0
    fi
    if ! docker image inspect package-builder >/dev/null 2>&1; then
        info "package-builder image missing; building it first"
        build_builder
    fi
    mkdir -p "$conda_repo"

    # Source packages with a top-level meta.yaml. Discover dynamically.
    # Then pin `autonomous-trust` to the front of the list: the other
    # subpackages list it in their `run:` requirements, so it must exist
    # in the local conda channel before they build (otherwise conda-build's
    # test-env solver fails with "autonomous-trust does not exist").
    local subpkgs=()
    local mypath
    for mypath in "$SRC_DIR"/*/meta.yaml; do
        [[ -f "$mypath" ]] || continue
        subpkgs+=("$(basename "$(dirname "$mypath")")")
    done
    if [[ ${#subpkgs[@]} -eq 0 ]]; then
        warn "no meta.yaml files under $SRC_DIR; nothing to build"
        return 0
    fi
    # Reorder: autonomous-trust first, everything else after.
    local ordered=()
    local sp
    for sp in "${subpkgs[@]}"; do
        [[ "$sp" == "autonomous-trust" ]] && ordered=("$sp" "${ordered[@]}") || ordered+=("$sp")
    done
    subpkgs=("${ordered[@]}")

    # Each build sees the in-progress local channel so dependent packages
    # find already-built siblings. Harmless for the first (autonomous-trust)
    # since it has no AT-internal deps. Conda-build auto-indexes the
    # output-folder after each successful build.
    #
    # `--no-test` skips conda-build's post-build test phase, including
    # the test-env resolution that otherwise tries to install `run`
    # requirements (including `autonomous-trust`) from the channel list.
    # The test-env solver does NOT inherit the `-c file:///build/dist`
    # channel reliably across conda-build versions, which makes
    # `autonomous-trust` look unavailable from `-inspector`/`-services`/
    # `-simulator` even when the package is already built and present.
    # None of our recipes define test commands, so `--no-test` only
    # skips env-resolution (which we don't need). Drop this flag if a
    # recipe gains real test commands and the channel issue is fixed.
    local extra_args='-c file:///build/dist --no-test'
    for sp in "${subpkgs[@]}"; do
        local src_pkg="$SRC_DIR/$sp"
        # Sweep stale conda-build artifacts from previous (possibly failed)
        # runs. `.conda/` is conda's per-user state dir created by `conda
        # build` when it can't write to its base cache; if left in the
        # mounted source dir, conda re-discovers it next run and tries to
        # re-apply patches from packages whose extracted recipe dirs are
        # gone — producing "no such patch:" errors. `.condarc` is the
        # accompanying conda config that pointed at it.
        rm -rf "$src_pkg/.conda" "$src_pkg/.condarc"
        # Also wipe the recipe's poetry output (./dist) so re-runs don't
        # confuse already-extracted wheels with newly-built ones.
        rm -rf "$src_pkg/dist"
        # Temporarily move heavy/problematic subtrees OUTSIDE the source
        # dir entirely. node_modules has tens of thousands of files plus
        # broken symlinks that crash `cp -a` during conda-build's
        # _copy_top_level_recipe step. Stash must be outside the bind-
        # mounted source — a sibling location inside the same dir still
        # gets walked by conda-build's recipe-copy. Production runtime
        # needs only the built wheel; node_modules is dev-time only.
        local stash="/tmp/at-builder-stash-$$-${sp//\//_}"
        local stashed=0
        if [[ -d "$src_pkg/reactjs/node_modules" ]]; then
            mv "$src_pkg/reactjs/node_modules" "$stash"
            stashed=1
            # Restore on any exit path (success/failure/Ctrl-C) so a stray
            # build crash doesn't leave the user with a missing
            # node_modules dir.
            # shellcheck disable=SC2064
            trap "[[ -d '$stash' && ! -e '$src_pkg/reactjs/node_modules' ]] && mv '$stash' '$src_pkg/reactjs/node_modules'" EXIT INT TERM
        fi
        info "running package-builder for $sp ..."
        docker run --rm -u "$(id -u):$(id -g)" \
            -e "EXTRA_ARGS=$extra_args" \
            -e "HOME=/tmp" \
            -v "$src_pkg:/build/src" \
            -v "$conda_repo:/build/dist" \
            -w /build/src \
            package-builder
        if (( stashed )); then
            mv "$stash" "$src_pkg/reactjs/node_modules"
            trap - EXIT INT TERM
        fi
        # Surface what got produced; if zero matching artifacts landed,
        # downstream builds will fail with confusing "channel doesn't
        # have this package" errors, so flag it early.
        local pkg_name="${sp//-/_}"
        local found
        found=$(find "$conda_repo" -name "${pkg_name}-*.conda" -o -name "${pkg_name}-*.tar.bz2" 2>/dev/null | head -1)
        if [[ -z "$found" ]]; then
            error "package-builder for $sp produced no ${pkg_name}-* artifact under $conda_repo"
            error "  inspect the conda-build output above for the real failure"
            return 1
        fi
        info "  → produced $(basename "$found")"
    done
}

build_release() {
    info "Building ${IMAGE_NAME} (release) ..."
    run_builder
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
    run_builder
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
    run_builder
    local args
    read -ra args <<< "$(common_build_args)"
    docker build "${args[@]}" \
        -t "${IMAGE_NAME}-lite" \
        -f "$AT_DIR/Dockerfile-lite" \
        "$REPO_DIR"
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
