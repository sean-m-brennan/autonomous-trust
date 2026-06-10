#!/bin/bash
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
# Build the C library

# Run everything relative to the repo root
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$here" || exit 1

if [[ "${CONDA_DEFAULT_ENV:-}" != "autonomous_trust" ]]; then
  echo "ERROR: conda environment 'autonomous_trust' is not active." >&2
  echo "  Run: conda activate autonomous_trust" >&2
  exit 1
fi

cd src/c || exit 1
rm -rf build
# Prefer clang if available (some GCC versions produce corrupt ELF objects).
# Also handle conda cross-compiler that may not exist on this system.
if [ -n "$CC" ] && ! command -v "$CC" >/dev/null 2>&1; then
  unset CC CXX CONDA_PREFIX
fi
if [ -z "$CC" ] && command -v clang >/dev/null 2>&1; then
  export CC=clang CXX=clang++
fi
# AT_ZTA=ON: build the Zero Trust credential integration so the native lib's
# public_identity_t carries the zta_credential_* fields (matches the CFFI cdef
# in core/_native/_ffi.py and the AT_ZTA=ON conformance build). Requires
# OpenSSL, which the conda env (required above) provides.
cmake -S . -B build -DAT_ZTA=ON
cd build || exit 1
make -j1
