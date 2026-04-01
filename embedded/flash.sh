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
# Flash an Autonomous Trust SD card image to a device.
#
# Usage:
#   sudo ./flash.sh autonomous-trust.img /dev/sdX

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RESET='\033[0m'

info()  { echo -e "${GREEN}[flash]${RESET} $*"; }
warn()  { echo -e "${YELLOW}[flash]${RESET} $*"; }
error() { echo -e "${RED}[flash]${RESET} $*" >&2; }

if [ $# -lt 2 ]; then
    echo "Usage: sudo $0 IMAGE DEVICE"
    echo "  IMAGE   Path to .img file"
    echo "  DEVICE  Target block device (e.g., /dev/sdX)"
    exit 1
fi

IMAGE="$1"
DEVICE="$2"

if [ "$(id -u)" -ne 0 ]; then
    error "Must be run as root (use sudo)"
    exit 1
fi

if [ ! -f "$IMAGE" ]; then
    error "Image not found: $IMAGE"
    exit 1
fi

if [ ! -b "$DEVICE" ]; then
    error "Not a block device: $DEVICE"
    exit 1
fi

# Safety: refuse to write to anything that looks like a system disk
case "$DEVICE" in
    /dev/sda|/dev/nvme0n1|/dev/vda|/dev/mmcblk0)
        error "Refusing to write to $DEVICE (looks like a system disk)"
        error "Specify the SD card device explicitly (e.g., /dev/sdb)"
        exit 1 ;;
esac

IMAGE_SIZE=$(stat -c%s "$IMAGE")
DEVICE_SIZE=$(blockdev --getsize64 "$DEVICE")

info "Image:  $IMAGE ($(numfmt --to=iec "$IMAGE_SIZE"))"
info "Device: $DEVICE ($(numfmt --to=iec "$DEVICE_SIZE"))"

if [ "$IMAGE_SIZE" -gt "$DEVICE_SIZE" ]; then
    error "Image is larger than device"
    exit 1
fi

warn "This will ERASE ALL DATA on $DEVICE"
read -rp "Type 'yes' to continue: " confirm
if [ "$confirm" != "yes" ]; then
    info "Aborted"
    exit 0
fi

info "Flashing ..."
dd if="$IMAGE" of="$DEVICE" bs=4M status=progress conv=fsync

info "Syncing ..."
sync

info "Done. Remove SD card and insert into the device."
