#!/usr/bin/env bash
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
# Verify an Autonomous Trust SD card image without booting it.
# Checks partition layout, rootfs contents, dm-verity, and binary signature.
#
# Works without loop devices by inspecting the Buildroot output images
# directly (pre-assembly files) and verifying the combined .img partition table.
#
# Usage:
#   ./verify-image.sh                          # auto-detect from build dir
#   ./verify-image.sh --images-dir path/to/images
#   ./verify-image.sh --pubkey path/to/key.pub

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/.buildroot-build"

IMAGES_DIR=""
PUBKEY="$SCRIPT_DIR/signing.pub"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
RESET='\033[0m'

info()  { echo -e "${GREEN}[verify-image]${RESET} $*"; }
warn()  { echo -e "${YELLOW}[verify-image]${RESET} $*"; }
error() { echo -e "${RED}[verify-image]${RESET} $*" >&2; }
step()  { echo -e "${CYAN}[verify-image]${RESET} === $* ==="; }

PASS=0
FAIL=0

check() {
    local desc="$1" result="$2"
    if [ "$result" -eq 0 ]; then
        info "  PASS: $desc"
        PASS=$((PASS + 1))
    else
        error "  FAIL: $desc"
        FAIL=$((FAIL + 1))
    fi
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --images-dir) IMAGES_DIR="$2"; shift 2 ;;
        --pubkey)     PUBKEY="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo
            echo "Options:"
            echo "  --images-dir DIR  Buildroot images directory"
            echo "  --pubkey PATH     Public key for binary signature check"
            exit 0 ;;
        *) error "Unknown option: $1"; exit 1 ;;
    esac
done

# Auto-detect images directory
if [ -z "$IMAGES_DIR" ]; then
    IMAGES_DIR="$BUILD_DIR/output/images"
fi

if [ ! -d "$IMAGES_DIR" ]; then
    error "Images directory not found: $IMAGES_DIR"
    exit 1
fi

SD_IMG="$IMAGES_DIR/autonomous-trust.img"

# -----------------------------------------------------------------------
# 1. SD card image partition layout
# -----------------------------------------------------------------------
step "Partition layout"

if [ -f "$SD_IMG" ]; then
    info "SD image: $SD_IMG ($(du -h "$SD_IMG" | cut -f1))"

    FDISK=$(command -v fdisk 2>/dev/null || command -v /sbin/fdisk 2>/dev/null || command -v /usr/sbin/fdisk 2>/dev/null || true)
    if [ -n "$FDISK" ]; then
        FDISK_OUT=$("$FDISK" -l "$SD_IMG" 2>/dev/null)
        echo "$FDISK_OUT" | grep -E "^$SD_IMG|^Disk |^Sector" | sed 's/^/  /'

        PART_COUNT=$(echo "$FDISK_OUT" | grep -c "^${SD_IMG}[0-9p]" || true)
        [ "$PART_COUNT" -eq 3 ] && rc=0 || rc=1
        check "Image has 3 partitions (boot, rootfs, data)" $rc

        echo "$FDISK_OUT" | grep "^${SD_IMG}" | sed 's/^/  /'

        echo "$FDISK_OUT" | grep -q "W95 FAT" && rc=0 || rc=1
        check "Partition 1 is FAT32 (boot)" $rc

        LINUX_PARTS=$(echo "$FDISK_OUT" | grep -c "Linux" || true)
        [ "$LINUX_PARTS" -ge 2 ] && rc=0 || rc=1
        check "Partitions 2-3 are Linux (rootfs + data)" $rc
    else
        warn "fdisk not found, skipping partition table check"
    fi
else
    warn "No assembled SD image found at $SD_IMG"
fi

# -----------------------------------------------------------------------
# 2. Boot partition contents (from boot.vfat using mdir)
# -----------------------------------------------------------------------
step "Boot partition"

BOOT_IMG="$IMAGES_DIR/boot.vfat"
if [ -f "$BOOT_IMG" ]; then
    info "Boot image: $(du -h "$BOOT_IMG" | cut -f1)"

    if command -v mdir &>/dev/null; then
        BOOT_LIST=$(mdir -i "$BOOT_IMG" :: 2>/dev/null || true)
        info "  Contents:"
        echo "$BOOT_LIST" | sed 's/^/    /'

        echo "$BOOT_LIST" | grep -qi "config" && rc=0 || rc=1
        check "config.txt present in boot" $rc

        echo "$BOOT_LIST" | grep -qi "u-boot" && rc=0 || rc=1
        check "u-boot.bin present in boot" $rc

        echo "$BOOT_LIST" | grep -qi "image" && rc=0 || rc=1
        check "Kernel Image present in boot" $rc

        echo "$BOOT_LIST" | grep -qi "dtb" && rc=0 || rc=1
        check "Device tree blob(s) present in boot" $rc

        # Extract and display config.txt (timeout prevents mcopy hangs)
        if command -v mcopy &>/dev/null; then
            TMP_CFG=$(mktemp)
            timeout 5 mcopy -n -i "$BOOT_IMG" "::config.txt" "$TMP_CFG" </dev/null 2>/dev/null \
                || timeout 5 mcopy -n -i "$BOOT_IMG" "::CONFIG.TXT" "$TMP_CFG" </dev/null 2>/dev/null \
                || true
            if [ -s "$TMP_CFG" ]; then
                info "  config.txt:"
                cat "$TMP_CFG" | sed 's/^/    /'
            fi
            rm -f "$TMP_CFG"
        fi
    else
        warn "  mtools (mdir) not found, skipping boot partition content check"
        # Fallback: check that the individual files exist in images dir
        [ -f "$IMAGES_DIR/u-boot.bin" ] && rc=0 || rc=1
        check "u-boot.bin built" $rc

        [ -f "$IMAGES_DIR/Image" ] && rc=0 || rc=1
        check "Kernel Image built" $rc

        ls "$IMAGES_DIR"/*.dtb &>/dev/null && rc=0 || rc=1
        check "Device tree blob(s) built" $rc
    fi
else
    warn "No boot.vfat found, checking individual boot files"
    [ -f "$IMAGES_DIR/u-boot.bin" ] && rc=0 || rc=1
    check "u-boot.bin built" $rc

    [ -f "$IMAGES_DIR/Image" ] && rc=0 || rc=1
    check "Kernel Image built" $rc

    ls "$IMAGES_DIR"/*.dtb &>/dev/null && rc=0 || rc=1
    check "Device tree blob(s) built" $rc
fi

# -----------------------------------------------------------------------
# 3. Root filesystem (inspect the ext4 image via debugfs or tar)
# -----------------------------------------------------------------------
step "Root filesystem"

ROOTFS_TAR="$IMAGES_DIR/rootfs.tar"
ROOTFS_EXT4="$IMAGES_DIR/rootfs.ext4"

# Prefer tar extraction (no root needed, no loop device)
if [ -f "$ROOTFS_TAR" ]; then
    info "Inspecting rootfs via tar archive"

    TAR_LIST=$(tar tf "$ROOTFS_TAR")

    echo "$TAR_LIST" | grep -q "usr/local/bin/at_demo$" && rc=0 || rc=1
    check "at_demo binary in rootfs" $rc

    echo "$TAR_LIST" | grep -q "etc/systemd/system/autonomous-trust.service" && rc=0 || rc=1
    check "systemd service file in rootfs" $rc

    echo "$TAR_LIST" | grep -q "multi-user.target.wants/autonomous-trust" && rc=0 || rc=1
    check "Service enabled (multi-user.target.wants)" $rc

    echo "$TAR_LIST" | grep -q "opt/autonomous-trust" && rc=0 || rc=1
    check "Data mount point /opt/autonomous-trust in rootfs" $rc

    # Check fstab
    FSTAB=$(tar xf "$ROOTFS_TAR" -O ./etc/fstab 2>/dev/null || true)
    if [ -n "$FSTAB" ]; then
        info "  fstab:"
        echo "$FSTAB" | sed 's/^/    /'
        echo "$FSTAB" | grep -q "ro" && rc=0 || rc=1
        check "Root filesystem marked read-only in fstab" $rc
        echo "$FSTAB" | grep -q "/opt/autonomous-trust" && rc=0 || rc=1
        check "Data partition in fstab" $rc
    fi

    # Verify static binary
    TMP_BIN=$(mktemp)
    tar xf "$ROOTFS_TAR" -O ./usr/local/bin/at_demo > "$TMP_BIN" 2>/dev/null || true
    if [ -s "$TMP_BIN" ]; then
        BINARY_INFO=$(file "$TMP_BIN")
        info "  Binary: $BINARY_INFO"
        echo "$BINARY_INFO" | grep -q "statically linked" && rc=0 || rc=1
        check "at_demo is statically linked" $rc
        echo "$BINARY_INFO" | grep -qi "ARM aarch64\|aarch64" && rc=0 || rc=1
        check "at_demo is ARM64 architecture" $rc
        BINARY_SIZE=$(wc -c < "$TMP_BIN")
        info "  Size: $(numfmt --to=iec "$BINARY_SIZE" 2>/dev/null || echo "${BINARY_SIZE} bytes")"
    fi

    # Check no package manager
    tar tf "$ROOTFS_TAR" | grep -q "usr/bin/apt-get" && rc=1 || rc=0
    check "No apt-get in rootfs" $rc
    tar tf "$ROOTFS_TAR" | grep -q "usr/bin/dpkg" && rc=1 || rc=0
    check "No dpkg in rootfs" $rc

    # File count
    FILE_COUNT=$(tar tf "$ROOTFS_TAR" | wc -l)
    info "  Total entries in rootfs: $FILE_COUNT"
else
    warn "No rootfs.tar found, skipping detailed rootfs inspection"
    [ -f "$ROOTFS_EXT4" ] && rc=0 || rc=1
    check "rootfs.ext4 image exists" $rc
fi

# Binary signature check (from the tar or overlay)
step "Binary signature"

if [ -n "${TMP_BIN:-}" ] && [ -s "${TMP_BIN:-}" ] && [ -f "$PUBKEY" ]; then
    # Extract sig from tar if present
    TMP_SIG="${TMP_BIN}.sig"
    tar xf "$ROOTFS_TAR" -O ./usr/local/bin/at_demo.sig > "$TMP_SIG" 2>/dev/null || true
    if [ -s "$TMP_SIG" ]; then
        "$SCRIPT_DIR/verify-binary.sh" --binary "$TMP_BIN" --pubkey "$PUBKEY" && rc=0 || rc=1
        check "Binary signature valid" $rc
    else
        warn "  No .sig in rootfs (build may not have used --sign)"
    fi
    rm -f "$TMP_SIG"
elif [ ! -f "$PUBKEY" ]; then
    warn "  Public key not found: $PUBKEY"
fi
rm -f "${TMP_BIN:-}" 2>/dev/null || true

# -----------------------------------------------------------------------
# 4. dm-verity
# -----------------------------------------------------------------------
step "dm-verity"

HASH_FILE="$IMAGES_DIR/root-hash.txt"
TABLE_FILE="$IMAGES_DIR/verity.table"
VERITY_IMG="$IMAGES_DIR/rootfs-verity.ext4"
VERITY_HASH="$IMAGES_DIR/rootfs.verity"

[ -f "$HASH_FILE" ] && rc=0 || rc=1
check "dm-verity root hash file exists" $rc

[ -f "$TABLE_FILE" ] && rc=0 || rc=1
check "dm-verity table file exists" $rc

[ -f "$VERITY_IMG" ] && rc=0 || rc=1
check "rootfs-verity.ext4 image exists" $rc

if [ -f "$HASH_FILE" ]; then
    ROOT_HASH=$(cat "$HASH_FILE")
    info "  Root hash: $ROOT_HASH"
    [ ${#ROOT_HASH} -eq 64 ] && rc=0 || rc=1
    check "Root hash is 64 hex chars (SHA-256)" $rc
fi

if [ -f "$TABLE_FILE" ]; then
    info "  Verity table:"
    cat "$TABLE_FILE" | sed 's/^/    /'
fi

if [ -f "$VERITY_IMG" ] && [ -f "$VERITY_HASH" ] && [ -f "$HASH_FILE" ] \
    && command -v veritysetup &>/dev/null; then
    veritysetup verify "$VERITY_IMG" "$VERITY_HASH" "$(cat "$HASH_FILE")" 2>/dev/null && rc=0 || rc=1
    check "dm-verity verification passes" $rc
else
    warn "  Skipping dm-verity verification (veritysetup not available or files missing)"
fi

# -----------------------------------------------------------------------
# 5. Size summary
# -----------------------------------------------------------------------
step "Size summary"

[ -f "$SD_IMG" ] && info "  SD card image:   $(du -h "$SD_IMG" | cut -f1)"
[ -f "$BOOT_IMG" ] && info "  Boot partition:  $(du -h "$BOOT_IMG" | cut -f1)"
[ -f "$ROOTFS_EXT4" ] && info "  Root filesystem: $(du -h "$ROOTFS_EXT4" | cut -f1)"
[ -f "$VERITY_IMG" ] && info "  Root + verity:   $(du -h "$VERITY_IMG" | cut -f1)"
[ -f "$IMAGES_DIR/data.ext4" ] && info "  Data partition:  $(du -h "$IMAGES_DIR/data.ext4" | cut -f1)"
[ -f "$IMAGES_DIR/Image" ] && info "  Kernel:          $(du -h "$IMAGES_DIR/Image" | cut -f1)"
[ -f "$IMAGES_DIR/u-boot.bin" ] && info "  U-Boot:          $(du -h "$IMAGES_DIR/u-boot.bin" | cut -f1)"

# -----------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------
echo
step "Results: $PASS passed, $FAIL failed"

if [ "$FAIL" -gt 0 ]; then
    error "Some checks failed. Review output above."
    exit 1
fi

info "All checks passed!"
