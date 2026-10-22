#!/usr/bin/env bash
# Build autonomous-trust-devel .deb/.rpm packages locally, one per distro, by
# running scripts/package-devel.sh inside each distro's container. Any
# architecture Docker can run: a foreign one (arm64 on an x86_64 host) runs
# under QEMU emulation, so expect a build to take several times longer than
# a native one.
#
# The default distros match .github/workflows/release-packages.yml; keep the
# two lists in step.
#
# Usage: package-devel-docker.sh [--arch ARCH] [--distro IMAGE]... VERSION [OUTDIR]
#   --arch ARCH      amd64 or arm64 (default: this host's)
#   --distro IMAGE   container image to build in, repeatable
#                    (default: ubuntu:22.04 ubuntu:24.04 debian:12 rockylinux:9 fedora:44)
#   VERSION          release version, e.g. v0.3.0 (a leading 'v' is dropped)
#   OUTDIR           where the packages land (default: dist/<ARCH>)
#
# Examples:
#   scripts/package-devel-docker.sh --arch arm64 v0.3.0
#   scripts/package-devel-docker.sh --arch arm64 --distro ubuntu:24.04 v0.3.0 /tmp/pkgs
#
# A foreign architecture needs QEMU registered with binfmt_misc on the host
# (Docker Desktop has it). On Linux, once per boot:
#   docker run --privileged --rm tonistiigi/binfmt --install arm64
set -euo pipefail

usage() { sed -n '/^# Usage/,/^[^#]/p' "$0" | sed '$d; s/^# \{0,1\}//' >&2; exit 2; }

case "$(uname -m)" in
    x86_64) arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    *) arch=$(uname -m) ;;
esac
host_arch=$arch
distros=()
while [ $# -gt 0 ]; do
    case "$1" in
        --arch) arch=$2; shift 2 ;;
        --distro) distros+=("$2"); shift 2 ;;
        -h|--help) usage ;;
        -*) echo "unknown option: $1" >&2; usage ;;
        *) break ;;
    esac
done
[ $# -ge 1 ] && [ $# -le 2 ] || usage
version=$1
case "$arch" in amd64|arm64) ;; *) echo "unsupported --arch: $arch" >&2; exit 2 ;; esac
[ ${#distros[@]} -gt 0 ] || distros=(ubuntu:22.04 ubuntu:24.04 debian:12 rockylinux:9 fedora:44)

here=$(cd "$(dirname "$0")/.." && pwd)
outdir=${2:-$here/dist/$arch}
mkdir -p "$outdir"
outdir=$(cd "$outdir" && pwd)

if [ "$arch" != "$host_arch" ] && [ "$(uname -s)" = Linux ]; then
    qemu=$([ "$arch" = arm64 ] && echo qemu-aarch64 || echo qemu-x86_64)
    if [ ! -e /proc/sys/fs/binfmt_misc/$qemu ]; then
        echo "No QEMU binfmt handler for $arch on this host. Register it with:" >&2
        echo "  docker run --privileged --rm tonistiigi/binfmt --install $arch" >&2
        exit 1
    fi
fi

# The checkout is mounted read-only (the build happens in the container's
# /tmp); only OUTDIR is writable, and its files are handed back to the caller.
failed=()
for image in "${distros[@]}"; do
    echo "=== $image ($arch)"
    if ! docker run --rm --platform "linux/$arch" \
            -v "$here:/src:ro" -v "$outdir:/out" -w /src "$image" \
            bash -c "scripts/package-devel.sh --deps '$version' /out \
                     && chown -R $(id -u):$(id -g) /out"; then
        failed+=("$image")
    fi
done

ls -l "$outdir"
if [ ${#failed[@]} -gt 0 ]; then
    echo "FAILED: ${failed[*]}" >&2
    exit 1
fi
