#!/bin/bash
# Build a python distribution for live use

# Run everything relative to this script
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
cd "$here" || exit 1

# FIXME ensure conda env is active

ARGS="$*"
if [[ "$ARGS" = "" ]]; then
  ARGS="--py --dist --c --zkp"
fi

if [[ "$ARGS" = *"--py"* ]]; then
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

  if [[ "$ARGS" = *"--dist"* ]]; then
    # Create and extract distros
    rm -rf dist
    mkdir -p dist
    dist_dir=$(cd dist; pwd)
    poetry build --format sdist -C src/autonomous-trust -o $dist_dir
    poetry build --format sdist -C src/autonomous-trust-inspector -o $dist_dir
    poetry build --format sdist -C src/autonomous-trust-services -o $dist_dir
    poetry build --format sdist -C src/autonomous-trust-simulator -o $dist_dir
    for tarball in "$dist_dir"/autonomous_trust*.tar.gz; do
      tar xzf "$tarball" -C "$dist_dir" --strip-components 1
    done
    rm -f "$dist_dir"/*.toml "$dist_dir"/PKG-INFO

    export AUTONOMOUS_TRUST_SRC=$here/dist/autonomous_trust
  fi
fi

# Build the ZKP Rust extension (requires rustc + maturin)
if [[ "$ARGS" = *"--zkp"* ]]; then
  zkp_dir="$here/src/autonomous-trust"
  if command -v cargo >/dev/null 2>&1 && command -v maturin >/dev/null 2>&1; then
    echo "========== Building ZKP module =========="
    (cd "$zkp_dir" && maturin develop --release --manifest-path rust/Cargo.toml)
  elif command -v cargo >/dev/null 2>&1; then
    echo "WARNING: maturin not found, skipping ZKP build (pip install maturin)" >&2
  else
    echo "WARNING: Rust toolchain not found, skipping ZKP build (install rustup)" >&2
  fi
fi

# Build the C library
if [[ "$ARGS" = *"--c"* ]]; then
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
  cmake -S . -B build
  cd build || exit 1
  make -j1
fi
