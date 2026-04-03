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
#
# Install Autonomous Trust on a bare-metal Linux device.
# Detects architecture, installs runtime deps, deploys the binary, and
# enables the systemd service.
#
# Prerequisites:
#   apt install -y qemu-kvm libvirt-daemon  bridge-utils virtinst libvirt-daemon-system libguestfs-tools libosinfo-bin  qemu-system virt-manager qemu-system-aarch64 qemu-efi-aarch64 qemu-utils cloud-utils
#
# Usage:
#   sudo ./install.sh                          # install from local tarball
#   sudo ./install.sh --tarball /path/to.tar.gz  # explicit tarball path

set -euo pipefail

INSTALL_PREFIX="/usr/local"
AT_ROOT="/opt/autonomous-trust"
SERVICE_NAME="autonomous-trust"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RESET='\033[0m'

info()  { echo -e "${GREEN}[install]${RESET} $*"; }
warn()  { echo -e "${YELLOW}[install]${RESET} $*"; }
error() { echo -e "${RED}[install]${RESET} $*" >&2; }

TARBALL=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --tarball) TARBALL="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: sudo $0 [OPTIONS]"
            echo
            echo "Options:"
            echo "  --tarball PATH   Path to architecture-specific tarball"
            echo "  -h, --help       Show this help"
            exit 0 ;;
        *) error "Unknown option: $1"; exit 1 ;;
    esac
done

# Must be root
if [ "$(id -u)" -ne 0 ]; then
    error "This script must be run as root (use sudo)"
    exit 1
fi

# Detect architecture
ARCH="$(uname -m)"
case "$ARCH" in
    aarch64|arm64) ARCH_LABEL="arm64" ;;
    x86_64)        ARCH_LABEL="amd64" ;;
    *)             error "Unsupported architecture: $ARCH"; exit 1 ;;
esac
info "Detected architecture: $ARCH_LABEL"

# Find tarball
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -z "$TARBALL" ]; then
    TARBALL="$SCRIPT_DIR/dist/autonomous-trust-${ARCH_LABEL}.tar.gz"
fi

if [ ! -f "$TARBALL" ]; then
    error "Tarball not found: $TARBALL"
    error "Run build-arm.sh first, or specify --tarball"
    exit 1
fi

# Install runtime dependencies
info "Installing runtime dependencies ..."
apt-get update -y
apt-get install -y --no-install-recommends \
    libsodium23 libjansson4 libuuid1 \
    libprotobuf-c1 libprotobuf32 \
    iproute2 iputils-ping
apt-get clean

# Extract binary and library
info "Installing from $TARBALL ..."
tar -xzf "$TARBALL" -C /

# Update shared library cache
ldconfig

# Verify binary
if ! "$INSTALL_PREFIX/bin/at_demo" --help &>/dev/null; then
    warn "at_demo --help returned non-zero (may be expected without config)"
fi

# Create data directories
mkdir -p "$AT_ROOT/etc/at" "$AT_ROOT/var/at"

# Install systemd service
info "Installing systemd service ..."
cp "$SCRIPT_DIR/autonomous-trust.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"

# Allow at_demo to restart its own service (Phase 3 fleet management)
info "Configuring sudoers for autonomous-trust restart ..."
echo "ALL ALL=(root) NOPASSWD: /usr/bin/systemctl restart $SERVICE_NAME" > /etc/sudoers.d/$SERVICE_NAME
chmod 440 /etc/sudoers.d/$SERVICE_NAME

info "Installation complete."
info ""
info "To start now:   systemctl start $SERVICE_NAME"
info "To check logs:  journalctl -u $SERVICE_NAME -f"
info ""
info "To customize, create /opt/autonomous-trust/etc/at/environment with:"
info "  LOG_LEVEL=debug"
info "  STARTUP_DELAY=5"
