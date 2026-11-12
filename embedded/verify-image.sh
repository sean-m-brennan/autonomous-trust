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
#   ./verify-image.sh --devel                  # the devel image's build
#
# The locked-down image must have no login and none of the devel image's
# debugging aids; the devel image must have all of them.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/.buildroot-build"

IMAGES_DIR=""
PUBKEY="$SCRIPT_DIR/signing.pub"
DEVEL=false

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
        --devel)      DEVEL=true; shift ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo
            echo "Options:"
            echo "  --images-dir DIR  Buildroot images directory"
            echo "  --pubkey PATH     Public key for binary signature check"
            echo "  --devel           Check the devel image (default: the locked-down one)"
            exit 0 ;;
        *) error "Unknown option: $1"; exit 1 ;;
    esac
done

# Auto-detect images directory
if [ -z "$IMAGES_DIR" ]; then
    if $DEVEL; then
        IMAGES_DIR="$BUILD_DIR/output-devel/images"
    else
        IMAGES_DIR="$BUILD_DIR/output/images"
    fi
fi
info "Checking the $($DEVEL && echo devel || echo locked-down) image in $IMAGES_DIR"

# Assert a check only the devel image passes: required there, refused here
devel_only() {
    local desc="$1" present="$2"
    if $DEVEL; then
        check "$desc" "$present"
    else
        [ "$present" -ne 0 ] && rc=0 || rc=1
        check "No $desc (locked-down)" $rc
    fi
}

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

        grep -qi "config" <<<"$BOOT_LIST" && rc=0 || rc=1
        check "config.txt present in boot" $rc

        grep -qi "u-boot" <<<"$BOOT_LIST" && rc=0 || rc=1
        check "u-boot.bin present in boot" $rc

        grep -qi "image" <<<"$BOOT_LIST" && rc=0 || rc=1
        check "Kernel Image present in boot" $rc

        grep -qi "dtb" <<<"$BOOT_LIST" && rc=0 || rc=1
        check "Device tree blob(s) present in boot" $rc

        grep -qi "start4.*elf" <<<"$BOOT_LIST" && rc=0 || rc=1
        check "Pi 4 firmware start4.elf present in boot" $rc

        grep -qi "fixup4.*dat" <<<"$BOOT_LIST" && rc=0 || rc=1
        check "Pi 4 firmware fixup4.dat present in boot" $rc

        mdir -i "$BOOT_IMG" ::extlinux/extlinux.conf &>/dev/null && rc=0 || rc=1
        check "U-Boot extlinux/extlinux.conf present in boot" $rc

        grep -qi "wpa_supplicant.conf.example" <<<"$BOOT_LIST" && rc=0 || rc=1
        check "wpa_supplicant.conf.example present in boot" $rc

        grep -qi "at-address.conf.example" <<<"$BOOT_LIST" && rc=0 || rc=1
        check "at-address.conf.example present in boot" $rc

        EXTLINUX=$(timeout 5 mtype -i "$BOOT_IMG" ::extlinux/extlinux.conf </dev/null 2>/dev/null || true)
        grep -q "console=tty1" <<<"$EXTLINUX" && rc=0 || rc=1
        devel_only "kernel console on HDMI (console=tty1)" $rc
        grep -q "earlycon=" <<<"$EXTLINUX" && rc=0 || rc=1
        devel_only "early console (earlycon=)" $rc

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
# 3. Kernel config
# -----------------------------------------------------------------------
step "Kernel config"

# The devel kernel embeds its config (CONFIG_IKCONFIG), gzipped between the
# IKCFG_ST and IKCFG_ED markers. The locked-down kernel does not, so its
# config is read from the build tree beside the images directory.
KERNEL_IMAGE="$IMAGES_DIR/Image"
KCONFIG=""
EMBEDDED=1
if [ -f "$KERNEL_IMAGE" ]; then
    KCFG_OFF=$(grep -abo IKCFG_ST "$KERNEL_IMAGE" | head -1 | cut -d: -f1 || true)
    if [ -n "$KCFG_OFF" ]; then
        KCONFIG=$(tail -c +$((KCFG_OFF + 9)) "$KERNEL_IMAGE" | gzip -dc 2>/dev/null || true)
        [ -n "$KCONFIG" ] && EMBEDDED=0
    fi
fi
devel_only "kernel config embedded in the Image (CONFIG_IKCONFIG)" $EMBEDDED
if [ -z "$KCONFIG" ]; then
    BUILD_KCONFIG=$(find "$IMAGES_DIR/../build" -maxdepth 2 -path '*/linux-[0-9]*/.config' 2>/dev/null | head -1)
    [ -n "$BUILD_KCONFIG" ] && KCONFIG=$(cat "$BUILD_KCONFIG")
fi

if [ -n "$KCONFIG" ]; then
    # Options the image cannot boot or run without
    for opt in TMPFS TMPFS_POSIX_ACL DEVTMPFS CGROUPS INOTIFY_USER FHANDLE \
               MMC_SDHCI_IPROC BCMGENET MODULE_SIG_FORCE; do
        grep -qx "CONFIG_$opt=y" <<<"$KCONFIG" && rc=0 || rc=1
        check "Kernel built with CONFIG_$opt=y" $rc
    done
    # The devel image's debugging aids
    for opt in DRM_SIMPLEDRM FRAMEBUFFER_CONSOLE LEDS_TRIGGER_HEARTBEAT IKCONFIG_PROC; do
        grep -qx "CONFIG_$opt=y" <<<"$KCONFIG" && rc=0 || rc=1
        devel_only "kernel CONFIG_$opt" $rc
    done
else
    check "Kernel config readable (embedded or in the build tree)" 1
fi

# -----------------------------------------------------------------------
# 4. Root filesystem (inspect the ext4 image via debugfs or tar)
# -----------------------------------------------------------------------
step "Root filesystem"

ROOTFS_TAR="$IMAGES_DIR/rootfs.tar"
ROOTFS_EXT4="$IMAGES_DIR/rootfs.ext4"

# Prefer tar extraction (no root needed, no loop device)
if [ -f "$ROOTFS_TAR" ]; then
    info "Inspecting rootfs via tar archive"

    TAR_LIST=$(tar tf "$ROOTFS_TAR")

    grep -q "usr/local/bin/at_demo$" <<<"$TAR_LIST" && rc=0 || rc=1
    check "at_demo binary in rootfs" $rc

    grep -q "etc/systemd/system/autonomous-trust.service" <<<"$TAR_LIST" && rc=0 || rc=1
    check "systemd service file in rootfs" $rc

    grep -q "multi-user.target.wants/autonomous-trust" <<<"$TAR_LIST" && rc=0 || rc=1
    check "Service enabled (multi-user.target.wants)" $rc

    grep -q "opt/autonomous-trust" <<<"$TAR_LIST" && rc=0 || rc=1
    check "Data mount point /opt/autonomous-trust in rootfs" $rc

    grep -q "usr/lib/systemd/systemd$" <<<"$TAR_LIST" && rc=0 || rc=1
    check "systemd is the init system" $rc

    grep -q "sys-subsystem-net-devices-wlan0.device.wants/at-wifi.service" <<<"$TAR_LIST" && rc=0 || rc=1
    check "Wi-Fi unit enabled (at-wifi.service on wlan0)" $rc

    grep -q "etc/systemd/network/20-eth0.network" <<<"$TAR_LIST" \
        && grep -q "etc/systemd/network/30-wlan0.network" <<<"$TAR_LIST" && rc=0 || rc=1
    check "networkd DHCP config for eth0 and wlan0" $rc

    grep -q "sbin/wpa_supplicant$" <<<"$TAR_LIST" && rc=0 || rc=1
    check "wpa_supplicant in rootfs" $rc

    grep -q "lib/firmware/brcm/brcmfmac43455-sdio.bin" <<<"$TAR_LIST" && rc=0 || rc=1
    check "CYW43455 Wi-Fi firmware in rootfs" $rc

    grep -q "lib/firmware/regulatory.db$" <<<"$TAR_LIST" && rc=0 || rc=1
    check "Wireless regulatory database in rootfs" $rc

    grep -q "network-online.target.wants/systemd-networkd-wait-online.service" <<<"$TAR_LIST" && rc=0 || rc=1
    check "DHCP gets a head start (systemd-networkd-wait-online enabled)" $rc

    grep -q "etc/systemd/system/at-address.service$" <<<"$TAR_LIST" \
        && grep -q "usr/libexec/at-address$" <<<"$TAR_LIST" \
        && grep -q "autonomous-trust.service.d/address.conf$" <<<"$TAR_LIST" && rc=0 || rc=1
    check "AT waits for its static address (at-address.service)" $rc

    grep -q "etc/wpa_supplicant/at-adhoc.conf$" <<<"$TAR_LIST" \
        && grep -q "at-wifi.service.wants/at-wifi-prefer-ap.timer" <<<"$TAR_LIST" \
        && grep -q "usr/libexec/at-wifi-prefer-ap$" <<<"$TAR_LIST" \
        && grep -q "bin/wpa_cli$" <<<"$TAR_LIST" && rc=0 || rc=1
    check "Wi-Fi falls back to the ad-hoc cell and back (at-adhoc.conf, prefer-ap timer, wpa_cli)" $rc

    grep -q "sysinit.target.wants/systemd-time-wait-sync.service" <<<"$TAR_LIST" \
        && grep -q "etc/systemd/system/autonomous-trust.service.d/time-sync.conf" <<<"$TAR_LIST" && rc=0 || rc=1
    check "AT waits for the clock to sync (systemd-time-wait-sync enabled)" $rc

    grep -q "local-fs-pre.target.wants/at-grow-data.service" <<<"$TAR_LIST" \
        && grep -q "usr/libexec/at-grow-data$" <<<"$TAR_LIST" \
        && grep -q "sbin/sfdisk$" <<<"$TAR_LIST" \
        && grep -q "bin/partx$" <<<"$TAR_LIST" \
        && grep -q "lib/systemd/systemd-growfs$" <<<"$TAR_LIST" && rc=0 || rc=1
    check "Data partition grows to fill the card (at-grow-data, sfdisk, partx, growfs)" $rc

    # Variant: the locked-down image has no way in; the devel image has SSH,
    # a serial login and the /DEVELOPMENT marker
    TAR_LONG=$(tar tvf "$ROOTFS_TAR")
    grep -q "^\./DEVELOPMENT$" <<<"$TAR_LIST" && rc=0 || rc=1
    devel_only "/DEVELOPMENT marker" $rc
    grep -q "sbin/dropbear$" <<<"$TAR_LIST" \
        && grep -q "multi-user.target.wants/dropbear.service" <<<"$TAR_LIST" && rc=0 || rc=1
    devel_only "SSH server (Dropbear, enabled)" $rc
    grep -q "root/.ssh/authorized_keys -> /boot/authorized_keys" <<<"$TAR_LONG" && rc=0 || rc=1
    devel_only "root's SSH keys read from /boot/authorized_keys" $rc
    grep -q "bin/tcpdump$" <<<"$TAR_LIST" && rc=0 || rc=1
    devel_only "tcpdump" $rc
    if ! $DEVEL; then
        rc=0
        for unit in getty@.service serial-getty@.service console-getty.service autovt@.service; do
            grep -q "etc/systemd/system/$unit -> /dev/null" <<<"$TAR_LONG" || rc=1
        done
        check "Every getty masked (no login prompt on any terminal)" $rc
        ROOT_PW=$(tar xf "$ROOTFS_TAR" -O ./etc/shadow 2>/dev/null | awk -F: '$1 == "root" {print $2}')
        [ "${ROOT_PW:0:1}" = "*" ] || [ "${ROOT_PW:0:1}" = "!" ] && rc=0 || rc=1
        check "Root account locked" $rc
    fi

    # Modules are signed and the kernel refuses unsigned ones, so a module
    # that lost its signature (e.g. to a strip pass) would never load
    BRCMFMAC_KO=$(grep -m1 "/brcmfmac.ko$" <<<"$TAR_LIST" || true)
    if [ -n "$BRCMFMAC_KO" ]; then
        tar xf "$ROOTFS_TAR" -O "$BRCMFMAC_KO" 2>/dev/null | tail -c 28 \
            | grep -q "~Module signature appended~" && rc=0 || rc=1
    else
        rc=1
    fi
    check "brcmfmac.ko present and signed" $rc

    # Check fstab
    FSTAB=$(tar xf "$ROOTFS_TAR" -O ./etc/fstab 2>/dev/null || true)
    if [ -n "$FSTAB" ]; then
        info "  fstab:"
        echo "$FSTAB" | sed 's/^/    /'
        echo "$FSTAB" | grep -q "ro" && rc=0 || rc=1
        check "Root filesystem marked read-only in fstab" $rc
        echo "$FSTAB" | grep -q "/opt/autonomous-trust" && rc=0 || rc=1
        check "Data partition in fstab" $rc
        echo "$FSTAB" | grep "/opt/autonomous-trust" | grep -q "x-systemd.growfs" && rc=0 || rc=1
        check "Data filesystem grows with its partition (x-systemd.growfs)" $rc
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
# 5. dm-verity
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
# 6. Size summary
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
