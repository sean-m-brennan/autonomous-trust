#!/usr/bin/env bash
# Build the autonomous-trust-devel package (C libraries + headers + pkg-config)
# as a .deb or .rpm for the distro this runs on. libautonomous_trust.so links
# that distro's libprotobuf, whose soname changes between releases, so each
# target distro gets its own package, built in its own container.
#
# .github/workflows/release-packages.yml runs this once per distro on release.
# Local equivalent (one distro):
#   docker run --rm -v "$PWD:/src" -w /src ubuntu:24.04 \
#       scripts/package-devel.sh --deps v0.3.0 dist
#
# Usage: package-devel.sh [--deps] VERSION OUTDIR
#   --deps   install the build dependencies first (apt or dnf; needs root)
#   VERSION  release version; a leading 'v' is dropped (v0.3.0 -> 0.3.0)
#   OUTDIR   where the package lands
set -euo pipefail

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
            libsodium-dev libjansson-dev uuid-dev \
            libprotobuf-dev protobuf-compiler libprotobuf-c-dev protobuf-c-compiler
    else
        if [ "${ID}" != fedora ]; then
            # EL: libsodium is in EPEL, protobuf-c-compiler in CRB.
            dnf install -y dnf-plugins-core epel-release
            dnf config-manager --set-enabled crb
        fi
        dnf install -y \
            gcc gcc-c++ make cmake git python3 python3-pip pkgconf-pkg-config rpm-build \
            libsodium-devel jansson-devel libuuid-devel \
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
    # ubuntu22.04, debian12: one package per distro, told apart by the release.
    extra=(-DCMAKE_INSTALL_LIBDIR="lib/$(dpkg-architecture -qDEB_HOST_MULTIARCH)"
           -DCPACK_DEBIAN_PACKAGE_RELEASE="1~${ID}${VERSION_ID}")
else
    generator=RPM
    # The release gets the dist tag (.el9, .fc44) from CPACK_RPM_PACKAGE_RELEASE_DIST.
    extra=(-DCMAKE_INSTALL_LIBDIR=lib64)
fi

build=$(mktemp -d)
trap 'rm -rf "$build"' EXIT
cmake -S "$here/src/c" -B "$build" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=/usr \
    -DREVISION="$version" \
    -DAT_CONFORMANCE=OFF \
    "${extra[@]}"
cmake --build "$build" -j"$(nproc)"
(cd "$build" && cpack -G "$generator")

mkdir -p "$outdir"
cp "$build"/*."${generator,,}" "$outdir"/
ls -l "$outdir"
