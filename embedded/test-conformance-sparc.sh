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
# Run the C conformance corpus big-endian, on SPARC V8 / LEON3 under user-mode
# QEMU (DV002 Volume 2, O5 / Task 4.5.5).
#
# Cross-compiles conformance_runner against the Buildroot sysroot from
# sparc/leon3_defconfig, runs it under qemu-sparc, then runs the same corpus
# through a native build and diffs the two. Every case the corpus pins passes
# natively, so any case that passes there and fails here is a byte-order,
# word-size or alignment defect in the C core.
#
# Usage:
#   ./test-conformance-sparc.sh                 # build sysroot if missing, SPARC + native + diff
#   ./test-conformance-sparc.sh --sparc-only    # skip the native baseline and diff
#   ./test-conformance-sparc.sh --no-clean      # reuse the build dirs

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
C_DIR="$REPO_DIR/src/c"
PY_DIR="$REPO_DIR/src/autonomous-trust"
TOOLCHAIN_FILE="$SCRIPT_DIR/sparc/leon3-toolchain.cmake"
DEFCONFIG="$SCRIPT_DIR/sparc/leon3_defconfig"

BUILDROOT_VERSION="${BUILDROOT_VERSION:-2026.02.3}"
BR_SRC="${AT_SPARC_BR_SRC:-/var/tmp/at-sparc-src}"
BR_DL="${AT_SPARC_BR_DL:-/var/tmp/at-sparc-dl}"
export AT_SPARC_BR_OUT="${AT_SPARC_BR_OUT:-/var/tmp/at-sparc-leon3}"
BUILD_ROOT="${AT_SPARC_BUILD_DIR:-/var/tmp/at-sparc-build}"
# Buildroot's own job count. host-protobuf is a heavy C++ build: at the default
# nproc+1 it OOMs a small VM. The variable is BR2_JLEVEL; BR2_JOBS is not a
# Buildroot option and is silently ignored.
BR_JLEVEL="${BR2_JLEVEL:-2}"
JOBS="${JOBS:-4}"

SPARC_ONLY=false
CLEAN=true

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RESET='\033[0m'

info()  { echo -e "${GREEN}[sparc]${RESET} $*"; }
warn()  { echo -e "${YELLOW}[sparc]${RESET} $*"; }
error() { echo -e "${RED}[sparc]${RESET} $*" >&2; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --sparc-only) SPARC_ONLY=true; shift ;;
        --no-clean)   CLEAN=false; shift ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo
            echo "Options:"
            echo "  --sparc-only   Run only the SPARC corpus (no native baseline or diff)"
            echo "  --no-clean     Reuse the C build dirs instead of wiping them"
            echo "  -h, --help     Show this help"
            echo
            echo "Environment:"
            echo "  AT_SPARC_BR_OUT     Buildroot output dir  (default /var/tmp/at-sparc-leon3)"
            echo "  AT_SPARC_BR_SRC     Buildroot source dir  (default /var/tmp/at-sparc-src)"
            echo "  AT_SPARC_BR_DL      Buildroot downloads   (default /var/tmp/at-sparc-dl)"
            echo "  AT_SPARC_BUILD_DIR  C build dirs go here  (default /var/tmp/at-sparc-build)"
            echo "  BR2_JLEVEL          Buildroot jobs        (default 2; more OOMs a 3 GB VM)"
            echo "  JOBS                C build jobs          (default 4)"
            echo "  AT_JANSSON_SOURCE_DIR  jansson tree, if not the third_party/jansson submodule"
            echo
            echo "Keep the build dirs off the repo mount; virtiofs/fuseblk corrupts objects."
            exit 0 ;;
        *) error "Unknown option: $1"; exit 1 ;;
    esac
done

for tool in cmake make qemu-sparc python3; do
    if ! command -v "$tool" &>/dev/null; then
        error "$tool is required but not found"
        exit 1
    fi
done

SYSROOT="$AT_SPARC_BR_OUT/host/sparc-buildroot-linux-uclibc/sysroot"

# ---------------------------------------------------------------------------
# Sysroot
# ---------------------------------------------------------------------------

# The job count, pinned in .config rather than only passed on the command
# line, so a later bare `make` in the output dir cannot fall back to nproc+1.
pin_config() {
    sed -i '/^BR2_JLEVEL=/d' "$AT_SPARC_BR_OUT/.config"
    echo "BR2_JLEVEL=$BR_JLEVEL" >> "$AT_SPARC_BR_OUT/.config"
    make -C "$AT_SPARC_BR_OUT" olddefconfig
}

build_sysroot() {
    if [[ ! -d "$BR_SRC/buildroot-$BUILDROOT_VERSION" ]]; then
        info "Fetching Buildroot $BUILDROOT_VERSION ..."
        mkdir -p "$BR_SRC"
        curl -fsSL "https://buildroot.org/downloads/buildroot-$BUILDROOT_VERSION.tar.xz" \
            | tar -xJ -C "$BR_SRC"
    fi
    mkdir -p "$AT_SPARC_BR_OUT" "$BR_DL"
    local br="$BR_SRC/buildroot-$BUILDROOT_VERSION"
    info "Building the LEON3 sysroot in $AT_SPARC_BR_OUT (BR2_JLEVEL=$BR_JLEVEL) ..."
    make -C "$br" O="$AT_SPARC_BR_OUT" BR2_DEFCONFIG="$DEFCONFIG" BR2_DL_DIR="$BR_DL" defconfig
    pin_config
    make -C "$AT_SPARC_BR_OUT" BR2_JLEVEL="$BR_JLEVEL"
}

# jansson is not here: the C core builds its own (src/c/cmake/vendored-jansson.cmake)
for lib in libsodium.so libuuid.so libprotobuf-c.so; do
    if [[ ! -e "$SYSROOT/usr/lib/$lib" ]]; then
        warn "Sysroot is missing $lib"
        build_sysroot
        break
    fi
done

# protoc --c_out finds protoc-gen-c on PATH. Take both from the Buildroot host
# tree so the generated code matches the target libprotobuf-c.
export PATH="$AT_SPARC_BR_OUT/host/bin:$PATH"
unset CONDA_PREFIX

# ---------------------------------------------------------------------------
# Builds
# ---------------------------------------------------------------------------

# The extension set matches scripts/test-conformance.sh, less ZTA: the sysroot
# has no OpenSSL, so the zta-* cases skip on both sides here.
CMAKE_ARGS=(-DAT_TESTS=OFF -DAT_FLEET_LIB=ON -DAT_DATA_SOURCE_LIB=ON -DAT_NET_DTN=ON)
if [[ -n "${AT_JANSSON_SOURCE_DIR:-}" ]]; then
    CMAKE_ARGS+=(-DAT_JANSSON_SOURCE_DIR="$AT_JANSSON_SOURCE_DIR")
fi

build_runner() {
    local dir="$1"; shift
    if $CLEAN && [[ -d "$dir" ]]; then
        rm -rf "$dir"
    fi
    cmake -S "$C_DIR" -B "$dir" "${CMAKE_ARGS[@]}" "$@" >/dev/null
    make -C "$dir" -j"$JOBS" conformance_runner at_conformance_json
}

SPARC_BUILD="$BUILD_ROOT/sparc"
NATIVE_BUILD="$BUILD_ROOT/native"
SPARC_RESULT="$SPARC_BUILD/conformance/results/c-sparc.json"
NATIVE_RESULT="$NATIVE_BUILD/conformance/results/c-native.json"

info "Cross-compiling conformance_runner for LEON3 in $SPARC_BUILD ..."
build_runner "$SPARC_BUILD" -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN_FILE"
file "$SPARC_BUILD/conformance/conformance_runner"

if ! $SPARC_ONLY; then
    info "Building the native baseline in $NATIVE_BUILD ..."
    build_runner "$NATIVE_BUILD"
fi

# ---------------------------------------------------------------------------
# Runs
# ---------------------------------------------------------------------------
#
# A harness that reports failing cases must not stop the script before the diff
# prints. Collect each exit code and fold them in at the end.

sparc_rc=0
native_rc=0
diff_rc=0

mkdir -p "$(dirname "$SPARC_RESULT")"
info "Running the corpus under qemu-sparc ..."
# -cpu LEON3: the toolchain emits CASA for atomics, which QEMU's default
# sparc32 CPU does not implement (SIGILL).
set +e
qemu-sparc -cpu LEON3 -L "$SYSROOT" \
    "$SPARC_BUILD/conformance/conformance_runner" \
    "$SPARC_BUILD/conformance/corpus-json" "$SPARC_RESULT"
sparc_rc=$?
set -e

if ! $SPARC_ONLY; then
    mkdir -p "$(dirname "$NATIVE_RESULT")"
    info "Running the corpus natively ..."
    set +e
    "$NATIVE_BUILD/conformance/conformance_runner" \
        "$NATIVE_BUILD/conformance/corpus-json" "$NATIVE_RESULT"
    native_rc=$?
    set -e

    echo
    info "Diff: native (lhs) vs sparc (rhs)"
    set +e
    (cd "$PY_DIR" && python3 -m conformance.harness.common.diff_results \
        "$NATIVE_RESULT" "$SPARC_RESULT")
    diff_rc=$?
    set -e
fi

echo
echo "==== sparc conformance summary ===="
echo "  sparc (qemu LEON3) : rc=$sparc_rc   $SPARC_RESULT"
if ! $SPARC_ONLY; then
    echo "  native baseline    : rc=$native_rc   $NATIVE_RESULT"
    echo "  native vs sparc    : rc=$diff_rc   (0 = no case passes on one and fails on the other)"
fi

if (( sparc_rc != 0 || native_rc != 0 || diff_rc != 0 )); then
    exit 1
fi
exit 0
