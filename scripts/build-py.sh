#!/bin/bash
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
# Build a python distribution for live use

# Run everything relative to the repo root
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$here" || exit 1

usage() {
  cat <<'EOF'
Usage: build-py.sh [proto-only] [-h|--help]

Build the Python source distributions for live use. Regenerates the Protobuf
interfaces, then builds and extracts sdists for the autonomous-trust packages
into ./dist.

Requires the 'autonomous_trust' conda environment to be active (run
'conda activate autonomous_trust').

Arguments:
  proto-only    Only regenerate Protobuf interfaces; skip building sdists.

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

# Generate the Protobuf interfaces
protobuf_src=src/protobuf
protobuf_py_dir=src/autonomous-trust
protobuf_py=$protobuf_py_dir/autonomous_trust/core/protobuf

# Check protoc's status explicitly. This script does not run under `set -e`,
# and the steps below it (touch, and the sdist build) succeed regardless, so
# without this a missing protoc or a malformed .proto exits 0 while leaving the
# bindings untouched -- callers see success and go on to build or test against
# the PREVIOUS .proto.
if ! protoc --python_out=$protobuf_py_dir -I $protobuf_src $(find $protobuf_src -name "*.proto"); then
  echo "ERROR: protoc failed; the Protobuf interfaces in" >&2
  echo "  $protobuf_py" >&2
  echo "  are unchanged and do NOT reflect $protobuf_src." >&2
  echo "  protoc: $(command -v protoc || echo 'not found on PATH')" >&2
  echo "  It is supplied by the 'autonomous_trust' env via libprotobuf." >&2
  exit 1
fi
# protoc emits no __init__.py, so every directory of the generated tree needs
# one seeded here to be importable.
#
# Two things this must get right, both learned the hard way:
#   - NEVER seed one into a __pycache__. That makes __pycache__ an importable
#     package, and `PackageHash` (core/_python/system.py) walks core with
#     pkgutil.walk_packages, so it imports it -- writing a NESTED
#     __pycache__/__pycache__, which the next run of this script then seeds in
#     turn. That ratchet added one level per run and reached 33 levels / 315
#     stray __init__.py. Worse, each stray file joins the walked module set, so
#     the package digest came to depend on how many times this script had run:
#     two nodes off identical source disagreed, and idprocess.py rejects a
#     mismatched digest as a counterfeit peer.
#   - Seed EVERY directory, not just the leaves. The former leaves-only scan
#     silently stopped seeding the real package dirs from run 2 onward, because
#     once a __pycache__ exists it is the leaf and its parent no longer is.
while IFS= read -r -d '' dir; do
  touch "$dir/__init__.py"
done < <(find "$protobuf_py" -type d -name '__pycache__' -prune -o -type d -print0)

if [[ "$*" != *"proto-only"* ]]; then
  # Create and extract distros
  rm -rf dist
  mkdir -p dist
  dist_dir=$(cd dist; pwd)
  poetry build --format sdist -C src/autonomous-trust -o $dist_dir
  poetry build --format sdist -C src/autonomous-trust-inspector -o $dist_dir
  poetry build --format sdist -C src/autonomous-trust-services -o $dist_dir
  poetry build --format sdist -C src/autonomous-trust-simulator -o $dist_dir
  poetry build --format sdist -C src/autonomous-trust-evaluation -o $dist_dir
  for tarball in "$dist_dir"/autonomous_trust*.tar.gz; do
    tar xzf "$tarball" -C "$dist_dir" --strip-components 1
  done
  rm -f "$dist_dir"/*.toml "$dist_dir"/PKG-INFO

  export AUTONOMOUS_TRUST_SRC=$here/dist/autonomous_trust
fi
