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
# Build the ZKP Rust extension (requires rustc + maturin)

# Run everything relative to the repo root
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$here" || exit 1

usage() {
  cat <<'EOF'
Usage: build-zkp.sh [-h|--help]

Build the ZKP Rust extension into the autonomous-trust package via maturin.
Skips with a warning if the Rust toolchain or maturin is unavailable.

Requires the 'autonomous_trust' conda environment to be active (run
'conda activate autonomous_trust').

Options:
  -h, --help    Show this help message and exit.
EOF
}

case "${1:-}" in
  -h|--help) usage; exit 0 ;;
esac

if [[ "${CONDA_DEFAULT_ENV:-}" != "autonomous_trust" ]]; then
  echo "ERROR: conda environment 'autonomous_trust' is not active." >&2
  echo "  Run: conda activate autonomous_trust" >&2
  exit 1
fi

zkp_dir="$here/src/autonomous-trust"
if command -v cargo >/dev/null 2>&1 && command -v maturin >/dev/null 2>&1; then
  echo "========== Building ZKP module =========="
  (cd "$zkp_dir" && maturin develop --release --manifest-path rust/Cargo.toml)
elif command -v cargo >/dev/null 2>&1; then
  echo "WARNING: maturin not found, skipping ZKP build (conda install -c conda-forge maturin)" >&2
else
  echo "WARNING: Rust toolchain not found, skipping ZKP build (install rustup)" >&2
fi
