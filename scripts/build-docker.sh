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

# Where run_builder() parks the dev-only subtrees listed in AT_STASH_RELS while
# conda-build walks a package dir (see run_builder for why they must move).
#
# It has to be OUTSIDE the bind-mounted package dir but is otherwise free, and
# the choice matters: this was /tmp, and `mv` is only a rename WITHIN one
# filesystem. With /tmp on a separate partition or a tmpfs -- the common case,
# and true even in the dev sandbox -- every run copied ~1.3GB per package onto
# that filesystem and back. A sibling of the package dirs is on the source tree's
# own filesystem, so the move costs nothing. Both .dockerignore files exclude it,
# so a strand can never reach a build context.
STASH_ROOT="$SRC_DIR/.at-builder-stash"
AT_STASH_RELS=("reactjs/node_modules" ".tox" ".venv" ".rustup")

# Pinned conda toolchain (ISSUES.md §9.1): MINIFORGE_IMAGE / MINIFORGE_VERSION.
# Absence is not fatal -- the Dockerfiles carry the same pin as ARG defaults.
TOOLCHAIN_PINS="$REPO_DIR/config/cfg/toolchain-pins.env"
if [[ -f "$TOOLCHAIN_PINS" ]]; then
    # shellcheck source=../config/cfg/toolchain-pins.env
    source "$TOOLCHAIN_PINS"
fi

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

# build_image() + reclaim_superseded_images(). Every target below rebuilds a
# FIXED tag unconditionally -- no `docker image inspect` guard -- so each run of
# this script orphans the previous generation of whatever it builds.
source "$SCRIPT_DIR/image-prune.sh"

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
    # Pinned conda base image (ISSUES.md §9.1). The Dockerfiles carry the same
    # value as an ARG default, so an un-passed build is still pinned; passing it
    # keeps the pins file authoritative when the two are edited out of step.
    if [[ -n "${MINIFORGE_IMAGE:-}" ]]; then
        args+=(--build-arg "MINIFORGE_IMAGE=$MINIFORGE_IMAGE")
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
    build_image "${IMAGE_NAME}-devel" "${args[@]}" \
        -f "$AT_DIR/Dockerfile-devel" \
        "$REPO_DIR"
    push_to_registry "${IMAGE_NAME}-devel" 2>/dev/null || true
}

build_test() {
    info "Building ${IMAGE_NAME}-test ..."
    local args
    read -ra args <<< "$(common_build_args)"
    build_image "${IMAGE_NAME}-test" "${args[@]}" \
        -f "$AT_DIR/Dockerfile-test" \
        "$AT_DIR"
    push_to_registry "${IMAGE_NAME}-test" 2>/dev/null || true
}

build_full_devel() {
    info "Building ${IMAGE_NAME}-full-devel ..."
    local args
    read -ra args <<< "$(common_build_args)"
    build_image "${IMAGE_NAME}-full-devel" "${args[@]}" \
        -f "$SRC_DIR/Dockerfile-devel" \
        "$REPO_DIR"
    push_to_registry "${IMAGE_NAME}-full-devel" 2>/dev/null || true
}

build_builder() {
    info "Building package-builder ..."
    local args
    read -ra args <<< "$(common_build_args)"
    build_image "package-builder" "${args[@]}" \
        -f "$SRC_DIR/Dockerfile-build" \
        "$SRC_DIR"
    push_to_registry "package-builder" 2>/dev/null || true
}

# Restore whatever a previous run stranded. The EXIT/INT/TERM trap below covers
# every ordinary failure, but not SIGKILL, an OOM kill, or a power loss -- and
# the stash paths used to embed $$, so a strand was unreachable by the next run
# (which minted a fresh name) and simply leaked ~1.3GB per kill. Deterministic
# paths, mirroring the source layout, are what make this recovery possible.
#
# Runs before any stashing, so an interrupted run self-heals on the next build.
reap_builder_stash() {
    [[ -d "$STASH_ROOT" ]] || return 0
    local pkg_dir pkg rel stashed dest
    for pkg_dir in "$STASH_ROOT"/*; do
        [[ -d "$pkg_dir" ]] || continue
        pkg="$(basename "$pkg_dir")"
        for rel in "${AT_STASH_RELS[@]}"; do
            stashed="$pkg_dir/$rel"
            [[ -e "$stashed" ]] || continue
            dest="$SRC_DIR/$pkg/$rel"
            if [[ -e "$dest" ]]; then
                # Destination was recreated (a `poetry install`, an `npm i`)
                # after the strand. Both copies are now real; deleting either is
                # the operator's call, not this script's.
                warn "stranded stash is redundant: $stashed"
                warn "    ($dest exists again) -- left in place; remove it manually"
                continue
            fi
            mkdir -p "$(dirname "$dest")"
            mv "$stashed" "$dest"
            info "restored $pkg/$rel stranded by an earlier interrupted run"
        done
    done
    # Drop the now-empty skeleton (and STASH_ROOT itself when fully drained).
    find "$STASH_ROOT" -depth -type d -empty -delete 2>/dev/null || true
}

# Build the restore command as a STRING with every path already expanded.
# Reads run_builder's locals by bash's dynamic scoping, which is safe HERE
# because run_builder is on the stack when the trap is installed -- whereas the
# trap itself can fire once that frame is gone (errexit propagating out of
# run_builder's caller), so the trap must not depend on those locals surviving.
_stash_restore_cmd() {
    local i out=""
    for i in "${!_stash_from[@]}"; do
        out+="[[ -e '${_stash_from[$i]}' && ! -e '${_stash_to[$i]}' ]] && mkdir -p \"\$(dirname '${_stash_to[$i]}')\" && mv '${_stash_from[$i]}' '${_stash_to[$i]}'; "
    done
    printf '%s' "$out"
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
        # Temporarily move heavy/problematic dev-only subtrees OUTSIDE the
        # source dir entirely. conda-build's recipe-copy (source: path: ./)
        # walks the whole tree:
        #   - reactjs/node_modules: tens of thousands of files plus broken
        #     symlinks that crash `cp -a` during _copy_top_level_recipe.
        #   - .tox / .venv: virtualenvs whose `bin/python` symlinks point at
        #     host paths absent in the container, so the copy emits "broken
        #     symlink - ignoring copy" warnings for each.
        #   - .rustup: the Rust toolchain dir (large; internal symlinks).
        # A sibling location inside the dir still gets walked, so the stash
        # must be OUTSIDE the bind-mounted source -- see STASH_ROOT for why it
        # is a sibling of the package dirs rather than /tmp. Production runtime
        # needs only the built wheel; all are dev-time only. Restore on any exit
        # path (success/failure/Ctrl-C) so a build crash doesn't lose them.
        local -a _stash_from=() _stash_to=()
        local _rel _sp_dest
        for _rel in "${AT_STASH_RELS[@]}"; do
            [[ -e "$src_pkg/$_rel" ]] || continue
            _sp_dest="$STASH_ROOT/$sp/$_rel"
            if [[ -e "$_sp_dest" ]]; then
                # reap_builder_stash() already had its chance; something else
                # owns this path. Never clobber it -- skip the stash and let
                # conda-build emit its copy warnings for this subtree instead.
                warn "not stashing $sp/$_rel: $_sp_dest is occupied"
                warn "    (a concurrent build-docker.sh, or a strand that could not be reaped)"
                continue
            fi
            mkdir -p "$(dirname "$_sp_dest")"
            mv "$src_pkg/$_rel" "$_sp_dest"
            _stash_from+=("$_sp_dest")
            _stash_to+=("$src_pkg/$_rel")
            # Refresh the trap after EVERY move rather than once after the loop:
            # a Ctrl-C or a failing mv partway through used to leave the moves
            # already made with no restore trap at all.
            # shellcheck disable=SC2064
            trap "$(_stash_restore_cmd)" EXIT INT TERM
        done
        info "running package-builder for $sp ..."
        docker run --rm -u "$(id -u):$(id -g)" \
            -e "EXTRA_ARGS=$extra_args" \
            -e "HOME=/tmp" \
            -v "$src_pkg:/build/src" \
            -v "$conda_repo:/build/dist" \
            -w /build/src \
            package-builder
        if (( ${#_stash_from[@]} )); then
            local _j
            for _j in "${!_stash_from[@]}"; do
                [[ -e "${_stash_from[$_j]}" && ! -e "${_stash_to[$_j]}" ]] && \
                    mkdir -p "$(dirname "${_stash_to[$_j]}")" && \
                    mv "${_stash_from[$_j]}" "${_stash_to[$_j]}"
            done
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
    # Everything is restored by here, so the stash skeleton is empty dirs; drop
    # them (STASH_ROOT included) rather than leaving a mystery directory in src/.
    if [[ -d "$STASH_ROOT" ]]; then
        find "$STASH_ROOT" -depth -type d -empty -delete 2>/dev/null || true
    fi
}

build_release() {
    info "Building ${IMAGE_NAME} (release) ..."
    run_builder
    local args
    read -ra args <<< "$(common_build_args)"
    build_image "${IMAGE_NAME}" "${args[@]}" \
        -f "$AT_DIR/Dockerfile" \
        "$SRC_DIR"
    push_to_registry "${IMAGE_NAME}" 2>/dev/null || true
}

build_full() {
    info "Building ${IMAGE_NAME}-full ..."
    run_builder
    local args
    read -ra args <<< "$(common_build_args)"
    build_image "${IMAGE_NAME}-full" "${args[@]}" \
        -f "$SRC_DIR/Dockerfile" \
        "$REPO_DIR"
    push_to_registry "${IMAGE_NAME}-full" 2>/dev/null || true
}

build_lite() {
    info "Building ${IMAGE_NAME}-lite ..."
    run_builder
    local args
    read -ra args <<< "$(common_build_args)"
    build_image "${IMAGE_NAME}-lite" "${args[@]}" \
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

    # Before anything builds, and for every target -- not just the ones that
    # call run_builder -- so a subtree stranded by a killed run is back in the
    # source tree (and out of the build contexts) as early as possible.
    reap_builder_stash

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

    # Reclaim the generation each fixed tag moved off. After the loop rather
    # than per-target: a target's old image can still be the recorded parent of
    # another target's old image until that one goes too, and push_to_registry
    # must first move any registry-prefixed tag onto the new image.
    reclaim_superseded_images

    info "Done"
}

main
