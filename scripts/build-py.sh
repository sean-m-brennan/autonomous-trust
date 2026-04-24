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

if [[ "${CONDA_DEFAULT_ENV:-}" != "autonomous_trust" ]]; then
  echo "ERROR: conda environment 'autonomous_trust' is not active." >&2
  echo "  Run: conda activate autonomous_trust" >&2
  exit 1
fi

# Generate the Protobuf interfaces
protobuf_src=src/protobuf
protobuf_py_dir=src/autonomous-trust
protobuf_py=$protobuf_py_dir/autonomous_trust/core/protobuf

protoc --python_out=$protobuf_py_dir -I $protobuf_src $(find $protobuf_src -name "*.proto")
leaves=$(find $protobuf_py -type d | sort -r | awk 'index(a,$0)!=1{a=$0;print}' | sort)
for leaf in $leaves; do
  touch "$leaf/__init__.py"
done
touch "$protobuf_py/__init__.py"

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
