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
# Build and install SPLAT! (hoche fork) into the active conda environment.
#
# Prerequisites:
#   conda activate muudd_simulation
#
# Installs: splat, srtm2sdf, and related utilities into $CONDA_PREFIX/bin/
set -euo pipefail

if [[ -z "${CONDA_PREFIX:-}" ]]; then
    echo "Error: activate muudd_simulation conda env first" >&2
    exit 1
fi

BUILD_DIR=$(mktemp -d)
trap "rm -rf $BUILD_DIR" EXIT

echo "Cloning hoche/splat into $BUILD_DIR ..."
cd "$BUILD_DIR"
git clone --depth 1 https://github.com/hoche/splat.git
cd splat

mkdir -p build && cd build

# Conda's gcc_linux-64 uses cross-compiler prefixed names.
# Set CC/CXX so CMake finds them.
if [[ -x "$CONDA_PREFIX/bin/x86_64-conda-linux-gnu-gcc" ]]; then
    export CC="$CONDA_PREFIX/bin/x86_64-conda-linux-gnu-gcc"
    export CXX="$CONDA_PREFIX/bin/x86_64-conda-linux-gnu-g++"
fi

cmake .. -DCMAKE_INSTALL_PREFIX="$CONDA_PREFIX"
make -j"$(nproc)"
make install

# Build and install utilities (srtm2sdf, usgs2sdf, etc.)
# The top-level CMakeLists.txt does not include utils/, so build separately.
# The utils CMakeLists.txt lacks a preamble (designed for add_subdirectory),
# so we wrap it with a standalone CMakeLists.txt.
echo ""
echo "Building SPLAT! utilities ..."
cd "$BUILD_DIR/splat"
mkdir -p build-utils && cd build-utils
cat > CMakeLists.txt <<'CMAKE_EOF'
cmake_minimum_required(VERSION 3.10)
project(splat-utils C)
add_subdirectory("${SPLAT_UTILS_DIR}" utils)
CMAKE_EOF
cmake . -DSPLAT_UTILS_DIR="$BUILD_DIR/splat/utils" -DCMAKE_INSTALL_PREFIX="$CONDA_PREFIX"
make -j"$(nproc)"
make install

echo ""
echo "SPLAT! installed to $CONDA_PREFIX/bin/"
echo "Binaries:"
ls "$CONDA_PREFIX/bin"/splat* "$CONDA_PREFIX/bin"/srtm2sdf* 2>/dev/null || true
splat -v 2>&1 | head -1 || true
