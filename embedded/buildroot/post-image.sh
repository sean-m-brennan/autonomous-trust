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

# Buildroot post-image script: generate dm-verity hash tree and assemble SD image
set -euo pipefail

IMAGES_DIR="$1"        # Buildroot passes the images directory
VARIANT="${2:-locked}" # BR2_ROOTFS_POST_SCRIPT_ARGS: "devel" from at_devel.fragment
ROOTFS="$IMAGES_DIR/rootfs.ext4"

echo "[post-image] Generating dm-verity hash tree ..."

if ! command -v veritysetup &>/dev/null; then
    echo "[post-image] WARNING: veritysetup not found, skipping dm-verity"
    echo "[post-image] Install cryptsetup to enable dm-verity"
else
    VERITY_HASH="$IMAGES_DIR/rootfs.verity"
    VERITY_TABLE="$IMAGES_DIR/verity.table"

    # Generate hash tree appended to a copy of the rootfs
    cp "$ROOTFS" "$IMAGES_DIR/rootfs-verity.ext4"
    veritysetup format "$IMAGES_DIR/rootfs-verity.ext4" "$VERITY_HASH" \
        > "$VERITY_TABLE"

    ROOT_HASH=$(grep "Root hash:" "$VERITY_TABLE" | awk '{print $3}')
    echo "[post-image] dm-verity root hash: $ROOT_HASH"
    echo "$ROOT_HASH" > "$IMAGES_DIR/root-hash.txt"

    ROOTFS="$IMAGES_DIR/rootfs-verity.ext4"
fi

echo "[post-image] Assembling boot partition ..."

# Create a FAT32 boot partition image from individual files:
#   - Pi firmware (start4.elf, fixup4.dat, etc.)
#   - U-Boot binary
#   - Kernel Image
#   - Device tree blobs
#   - config.txt, cmdline.txt
BOOT_IMG="$IMAGES_DIR/boot.vfat"
BOOT_SIZE_MB=64
dd if=/dev/zero of="$BOOT_IMG" bs=1M count="$BOOT_SIZE_MB"
mkfs.vfat -n "BOOT" "$BOOT_IMG"

# Helper: copy file into the FAT image using mcopy
# mcopy is from mtools; if not available, fall back to mount+cp
copy_to_boot() {
    local src="$1" dst="$2"
    if command -v mcopy &>/dev/null; then
        mcopy -i "$BOOT_IMG" "$src" "::$dst"
    else
        echo "[post-image] WARNING: mcopy not found, skipping $src"
    fi
}

mmd_boot() {
    if command -v mmd &>/dev/null; then
        mmd -i "$BOOT_IMG" "::$1" 2>/dev/null || true
    fi
}

# Pi firmware files (from rpi-firmware package)
FW_DIR="$IMAGES_DIR/rpi-firmware"
if [ -d "$FW_DIR" ]; then
    for f in "$FW_DIR"/*.elf "$FW_DIR"/*.dat "$FW_DIR"/*.bin; do
        [ -f "$f" ] && copy_to_boot "$f" "$(basename "$f")"
    done
    # Copy overlays directory
    if [ -d "$FW_DIR/overlays" ]; then
        mmd_boot "overlays"
        for f in "$FW_DIR/overlays"/*; do
            [ -f "$f" ] && copy_to_boot "$f" "overlays/$(basename "$f")"
        done
    fi
    # cmdline.txt
    [ -f "$FW_DIR/cmdline.txt" ] && copy_to_boot "$FW_DIR/cmdline.txt" "cmdline.txt"
fi

# config.txt for Pi4. The firmware loads bcm2711-rpi-4-b.dtb (the mainline
# DTB, from the kernel build) and hands it to U-Boot. enable_uart fixes the
# core clock so the mini UART console on GPIO 14/15 keeps its baud rate.
cat > "$IMAGES_DIR/config.txt" <<'CONFIG'
# Autonomous Trust Pi4 boot config
arm_64bit=1
kernel=u-boot.bin
enable_uart=1
CONFIG
copy_to_boot "$IMAGES_DIR/config.txt" "config.txt"

# U-Boot's distro boot reads extlinux/extlinux.conf from the first
# partition. With no fdt line, U-Boot passes on the firmware's DTB. The
# root partition is named by PARTUUID (disk ID set by sfdisk below), because
# the SD card's mmcblk number depends on probe order. net.ifnames=0 keeps the
# kernel's eth0 and wlan0: systemd would otherwise rename the Ethernet port
# end0 (from the device tree's ethernet0 alias), and the .network files and
# at-wifi.service name eth0 and wlan0.
#
# The kernel logs to the mini UART (ttyS1). The devel image also logs to HDMI
# (tty1); the last console= is /dev/console, so systemd's boot status shows
# there. Its earlycon prints on the mini UART from the kernel's first
# instructions, before the UART driver loads.
CMDLINE="root=PARTUUID=41540001-02 rootfstype=ext4 rootwait ro net.ifnames=0"
if [ "$VARIANT" = devel ]; then
    CMDLINE="$CMDLINE earlycon=uart8250,mmio32,0xfe215040 console=ttyS1,115200 console=tty1"
else
    CMDLINE="$CMDLINE console=ttyS1,115200"
fi
cat > "$IMAGES_DIR/extlinux.conf" <<EXTLINUX
default at
timeout 0

label at
    kernel /Image
    append $CMDLINE
EXTLINUX
mmd_boot "extlinux"
copy_to_boot "$IMAGES_DIR/extlinux.conf" "extlinux/extlinux.conf"

# Wi-Fi credentials are not built in. Copy this file to wpa_supplicant.conf
# on the boot partition and fill in the network; at-wifi.service reads it.
cat > "$IMAGES_DIR/wpa_supplicant.conf.example" <<'WPA'
# Copy to wpa_supplicant.conf on this partition and fill in your network.
# Use plain LF line endings.
#
# When the network is out of range, the node joins or starts the AT ad-hoc
# cell, and it moves back here once the network is in range again. To run
# with no router at all, keep only the country line.
country=US

network={
    ssid="YOUR-SSID"
    psk="YOUR-PASSPHRASE"
}
WPA
copy_to_boot "$IMAGES_DIR/wpa_supplicant.conf.example" "wpa_supplicant.conf.example"

# The node's address. Without at-address.conf the node keeps its first DHCP
# lease as its address, so it needs a router on its first boot.
cat > "$IMAGES_DIR/at-address.conf.example" <<'ADDR'
# Copy to at-address.conf on this partition to give this node a fixed
# address. Use plain LF line endings.
#
# AT keeps the address it first starts with, on the router's network and in
# the ad-hoc cell alike. Give every node an address in one subnet, unique to
# the node; without a router it must not overlap anything else on the air.
# Without this file the node uses its first DHCP lease, so it needs a router
# on its first boot.
ADDRESS=10.42.0.11/16

# wlan0 when wpa_supplicant.conf is on this partition, eth0 otherwise
#INTERFACE=wlan0
ADDR
copy_to_boot "$IMAGES_DIR/at-address.conf.example" "at-address.conf.example"

# U-Boot
[ -f "$IMAGES_DIR/u-boot.bin" ] && copy_to_boot "$IMAGES_DIR/u-boot.bin" "u-boot.bin"

# Kernel and DTBs (loaded by U-Boot)
[ -f "$IMAGES_DIR/Image" ] && copy_to_boot "$IMAGES_DIR/Image" "Image"
for dtb in "$IMAGES_DIR"/*.dtb; do
    [ -f "$dtb" ] && copy_to_boot "$dtb" "$(basename "$dtb")"
done

echo "[post-image] Assembling SD card image ..."

# Create the data partition (empty ext4, writable). It is small so that the
# image fits any card; at-grow-data.service grows it to fill the card on the
# first boot.
DATA_IMG="$IMAGES_DIR/data.ext4"
dd if=/dev/zero of="$DATA_IMG" bs=1M count=64
mkfs.ext4 -q -L "at-data" "$DATA_IMG"

# Assemble: boot (64MB) + rootfs (128MB + verity) + data (64MB)
SD_IMG="$IMAGES_DIR/autonomous-trust.img"

# Calculate sizes in sectors (512 bytes each)
BOOT_SIZE=$(wc -c < "$BOOT_IMG")
ROOT_SIZE=$(wc -c < "$ROOTFS")
DATA_SIZE=$(wc -c < "$DATA_IMG")

BOOT_SECTORS=$((BOOT_SIZE / 512))
ROOT_SECTORS=$((ROOT_SIZE / 512))
DATA_SECTORS=$((DATA_SIZE / 512))

# Partition layout: 2048 sector gap, then boot, rootfs, data
BOOT_START=2048
ROOT_START=$((BOOT_START + BOOT_SECTORS))
DATA_START=$((ROOT_START + ROOT_SECTORS))
TOTAL_SECTORS=$((DATA_START + DATA_SECTORS + 2048))

# Create empty image
dd if=/dev/zero of="$SD_IMG" bs=512 count="$TOTAL_SECTORS"

# Create partition table. The fixed disk ID gives the partitions the
# PARTUUIDs 41540001-01/02/03 that extlinux.conf and fstab mount by.
sfdisk "$SD_IMG" <<PARTS
label: dos
label-id: 0x41540001
unit: sectors

${SD_IMG}1 : start=$BOOT_START, size=$BOOT_SECTORS, type=c
${SD_IMG}2 : start=$ROOT_START, size=$ROOT_SECTORS, type=83
${SD_IMG}3 : start=$DATA_START, size=$DATA_SECTORS, type=83
PARTS

# Write partition contents
dd if="$BOOT_IMG" of="$SD_IMG" bs=512 seek="$BOOT_START" conv=notrunc
dd if="$ROOTFS"   of="$SD_IMG" bs=512 seek="$ROOT_START" conv=notrunc
dd if="$DATA_IMG" of="$SD_IMG" bs=512 seek="$DATA_START" conv=notrunc

echo "[post-image] SD card image: $SD_IMG ($(du -h "$SD_IMG" | cut -f1))"
echo "[post-image] Done"
