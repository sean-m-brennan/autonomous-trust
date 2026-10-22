#!/usr/bin/env bash
# Build the autonomous-trust-devel package (C library + headers + pkg-config)
# and one autonomous-trust-<extension>-devel package per extension, each
# requiring the core package at the same version, as .debs or .rpms for the
# distro this runs on. Every extension is built; DTN with the uD3TN AAP 2.0
# (ud3tnv2) backend, whose aap2.proto comes from the ud3tn submodule. The library's dependencies
# (libsodium, jansson, protobuf-c, libuuid) keep one soname across distros, and
# glibc runs forward, so a package built on the oldest distro of a family
# installs on the newer ones: ubuntu:22.04 for Ubuntu 22.04+ and Debian 12+,
# rockylinux:9 for EL9+ and Fedora.
#
# .github/workflows/release-packages.yml runs this in those two containers on
# release. Local equivalent (one package; scripts/package-devel-docker.sh runs
# both, for any architecture):
#   docker run --rm -v "$PWD:/src" -w /src ubuntu:22.04 \
#       scripts/package-devel.sh --deps v0.3.0 dist
#
# Usage: package-devel.sh [--deps] VERSION OUTDIR
#   --deps   install the build dependencies first (apt or dnf; needs root)
#   VERSION  release version; a leading 'v' is dropped (v0.3.0 -> 0.3.0)
#   OUTDIR   where the package lands
set -euo pipefail

# The whole script is one { ... } block, so bash reads it all before running
# any of it: an edit to this file during a long run (the package install, the
# build) cannot make the running copy resume mid-line in the new text.
{

deps=0
if [ "${1:-}" = "--deps" ]; then deps=1; shift; fi
if [ $# -ne 2 ]; then
    sed -n '/^# Usage/,/^[^#]/p' "$0" | sed '$d; s/^# \{0,1\}//' >&2
    exit 2
fi
version=${1#v}
outdir=$2

here=$(cd "$(dirname "$0")/.." && pwd)
. /etc/os-release

install_deps() {
    if command -v apt-get >/dev/null; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update
        apt-get install -y --no-install-recommends \
            build-essential cmake git python3 python3-pip pkg-config dpkg-dev file \
            libsodium-dev libjansson-dev uuid-dev libssl-dev \
            libprotobuf-dev protobuf-compiler libprotobuf-c-dev protobuf-c-compiler
    else
        if [ "${ID}" != fedora ]; then
            # EL: libsodium is in EPEL, protobuf-c-compiler in CRB.
            dnf install -y dnf-plugins-core epel-release
            dnf config-manager --set-enabled crb
        fi
        dnf install -y \
            gcc gcc-c++ make cmake git python3 python3-pip pkgconf-pkg-config rpm-build \
            libsodium-devel jansson-devel libuuid-devel openssl-devel \
            protobuf-devel protobuf-compiler protobuf-c-devel protobuf-c-compiler
    fi
    # CMakeLists.txt needs 3.23; Ubuntu 22.04 ships 3.22.
    if ! printf '3.23\n%s\n' "$(cmake --version | awk 'NR==1{print $3}')" | sort -VC; then
        python3 -m pip install 'cmake~=3.31'
        hash -r
    fi
}
[ $deps -eq 1 ] && install_deps

if command -v dpkg-architecture >/dev/null; then
    generator=DEB
    extra=(-DCMAKE_INSTALL_LIBDIR="lib/$(dpkg-architecture -qDEB_HOST_MULTIARCH)")
else
    generator=RPM
    extra=(-DCMAKE_INSTALL_LIBDIR=lib64)
fi

build=$(mktemp -d)
trap 'rm -rf "$build"' EXIT

# Build from a copy of the sources the package needs, which leaves the checkout
# untouched (the docker wrapper mounts it read-only). The copy leaves out local
# build trees, the DTN submodules but for ud3tn's aap2.proto, and any leftover
# src/c/autonomous_trust/version.h (git-ignored, from an old build): CMake
# generates version.h only when the source tree has none, so a leftover one
# would ship in place of this version.
aap2=src/c/third_party/ud3tn/components/aap2/aap2.proto
if [ ! -f "$here/$aap2" ]; then
    echo "$aap2 missing: the DTN extension needs the ud3tn submodule:" >&2
    echo "  git submodule update --init --depth 1 src/c/third_party/ud3tn" >&2
    exit 1
fi
mkdir "$build/src"
(cd "$here" && tar -cf - \
    --exclude='src/c/build*' \
    --exclude='src/c/third_party/ION-DTN' \
    --exclude='src/c/third_party/ud3tn' \
    --exclude='src/c/autonomous_trust/version.h' \
    LICENSE src/c src/protobuf) | tar -xmf - -C "$build/src"
mkdir -p "$build/src/$(dirname "$aap2")"
cp "$here/$aap2" "$build/src/$aap2"

cmake -S "$build/src/src/c" -B "$build/bin" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=/usr \
    -DREVISION="$version" \
    -DAT_CONFORMANCE=OFF -DAT_TESTS=OFF \
    -DAT_RENDEZVOUS_LIB=ON -DAT_FIRST_CONTACT_LIB=ON -DAT_NET_GATEWAY=ON \
    -DAT_ORACLE_PHYSICS=ON -DAT_ORACLE_CALIBRATION=ON -DAT_ORACLE_CERTIFICATES=ON \
    -DAT_ORACLE_PREQUENTIAL=ON -DAT_ORACLE_REPLICATION=ON -DAT_ORACLE_SELECTION=ON \
    -DAT_ZTA=ON -DAT_FLEET_LIB=ON -DAT_DATA_SOURCE_LIB=ON \
    -DAT_NET_DTN=ON -DAT_NET_DTN_BACKEND=ud3tnv2 \
    "${extra[@]}"
cmake --build "$build/bin" -j"$(nproc)"
(cd "$build/bin" && cpack -G "$generator")

mkdir -p "$outdir"
cp "$build"/bin/*."${generator,,}" "$outdir"/
ls -l "$outdir"
exit
}
