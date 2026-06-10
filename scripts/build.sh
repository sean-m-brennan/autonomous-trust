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
# Build a python distribution for live use

# Run everything relative to the repo root
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$here" || exit 1

set -e

usage() {
  cat <<'EOF'
Usage: build.sh [WHAT] [extra args...] [-h|--help]

Top-level build dispatcher. WHAT selects which components to build; any extra
arguments are forwarded to the underlying build scripts.

WHAT (substring-matched; default: "py c zkp docker"):
  py             Build the Python distributions (build-py.sh).
  zkp | zero     Build the ZKP Rust extension (build-zkp.sh).
  c | native     Build the native C library (build-native.sh).
  docker         Build the Docker images (build-docker.sh all).

Examples:
  build.sh                 # build everything
  build.sh c               # build only the native C library
  build.sh "py c"          # build Python + native
  build.sh py proto-only   # forward 'proto-only' to build-py.sh

Options:
  -h, --help    Show this help message and exit.
EOF
}

case "${1:-}" in
  -h|--help) usage; exit 0 ;;
esac

WHAT="$1"
if [ -n "$WHAT" ]; then
  shift
fi
if [[ "$WHAT" = "" ]]; then
  WHAT="py c zkp docker"
fi

if [[ "$WHAT" = *"py"* ]]; then
  scripts/build-py.sh $@
fi

if [[ "$WHAT" = *"zkp"* ]] || [[ "$WHAT" = *"zero"* ]]; then
  scripts/build-zkp.sh $@
fi

if [[ "$WHAT" = *"c"* ]] || [[ "$WHAT" = *"native"* ]]; then
  scripts/build-native.sh $@
fi

if [[ "$WHAT" = *"docker"* ]]; then
  scripts/build-docker.sh all $@
fi
