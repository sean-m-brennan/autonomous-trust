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

# Buildroot post-build script: inject at_demo, configure fstab, and set up
# the locked-down or devel variant
set -euo pipefail

TARGET_DIR="$1"        # Buildroot passes the target rootfs directory
VARIANT="${2:-locked}" # BR2_ROOTFS_POST_SCRIPT_ARGS: "devel" from at_devel.fragment

echo "[post-build] Injecting at_demo binary ..."

# The static binary is placed in the overlay by build-image.sh
if [ ! -f "$TARGET_DIR/usr/local/bin/at_demo" ]; then
    echo "[post-build] ERROR: at_demo not found in overlay at $TARGET_DIR/usr/local/bin/"
    exit 1
fi

chmod 755 "$TARGET_DIR/usr/local/bin/at_demo"

# Create the data partition mount point
mkdir -p "$TARGET_DIR/opt/autonomous-trust"

mkdir -p "$TARGET_DIR/boot"

# Configure fstab: rootfs is read-only, data partition is read-write.
# Partitions are named by PARTUUID because the mainline Pi 4 device tree has
# no mmc aliases, so the SD card is mmcblk0 or mmcblk1 depending on whether
# its controller probes before the Wi-Fi SDIO controller. post-image.sh
# writes the MBR disk ID 0x41540001. /boot holds wpa_supplicant.conf, so it
# is readable by root only. at-grow-data.service grows the data partition to
# the end of the card before it is mounted, and x-systemd.growfs grows its
# filesystem to match.
cat > "$TARGET_DIR/etc/fstab" <<'FSTAB'
# <device>              <mount>                  <type>  <options>                <dump> <pass>
PARTUUID=41540001-01    /boot                    vfat    ro,umask=0077            0      2
PARTUUID=41540001-02    /                        ext4    ro,noatime               0      1
PARTUUID=41540001-03    /opt/autonomous-trust    ext4    rw,noatime,nosuid,x-systemd.growfs 0 2
FSTAB

if [ "$VARIANT" = devel ]; then
    echo "[post-build] Devel image: SSH, serial login, /DEVELOPMENT"

    # Host keys persist on the data partition; Buildroot's default points
    # /etc/dropbear at /var/run, which would mean new keys every boot
    rm -rf "$TARGET_DIR/etc/dropbear"
    ln -s /opt/autonomous-trust/dropbear "$TARGET_DIR/etc/dropbear"

    # Root's SSH keys come from the boot partition, like the Wi-Fi settings
    mkdir -p "$TARGET_DIR/root/.ssh"
    chmod 700 "$TARGET_DIR/root" "$TARGET_DIR/root/.ssh"
    ln -sfn /boot/authorized_keys "$TARGET_DIR/root/.ssh/authorized_keys"

    # Tells anyone on the node which image it runs
    cat > "$TARGET_DIR/DEVELOPMENT" <<DEVEL
This is an AutonomousTrust DEVELOPMENT image. Do not field it.

It differs from the locked-down image in that it has:
  - an SSH server (Dropbear, keys only; root's keys are /boot/authorized_keys)
  - a root login with no password on the serial console (ttyS1, 115200 baud)
  - the kernel console on HDMI and early console output on the mini UART
  - the ACT LED heartbeat and the kernel config at /proc/config.gz
  - full busybox and tcpdump

Built ${AT_BUILD_DATE:-unknown date} from ${AT_BUILD_DESC:-an unknown commit}.
DEVEL
else
    echo "[post-build] Locked-down image: no logins"

    # No login prompt on any terminal. Masking the templates covers the
    # instances systemd's getty generator would start for each console=.
    for unit in getty@.service serial-getty@.service console-getty.service \
                autovt@.service container-getty@.service; do
        ln -sfn /dev/null "$TARGET_DIR/etc/systemd/system/$unit"
    done
fi

# Remove unnecessary files to minimize image
rm -rf "$TARGET_DIR/usr/share/man"
rm -rf "$TARGET_DIR/usr/share/doc"
rm -rf "$TARGET_DIR/usr/share/locale"

echo "[post-build] Done"
