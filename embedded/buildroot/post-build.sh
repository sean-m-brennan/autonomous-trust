#!/usr/bin/env bash
# Buildroot post-build script: inject at_demo and configure fstab
set -euo pipefail

TARGET_DIR="$1"  # Buildroot passes the target rootfs directory

echo "[post-build] Injecting at_demo binary ..."

# The static binary is placed in the overlay by build-image.sh
if [ ! -f "$TARGET_DIR/usr/local/bin/at_demo" ]; then
    echo "[post-build] ERROR: at_demo not found in overlay at $TARGET_DIR/usr/local/bin/"
    exit 1
fi

chmod 755 "$TARGET_DIR/usr/local/bin/at_demo"

# Create the data partition mount point
mkdir -p "$TARGET_DIR/opt/autonomous-trust"

# Configure fstab: rootfs is read-only, data partition is read-write
cat > "$TARGET_DIR/etc/fstab" <<'FSTAB'
# <device>       <mount>                  <type>  <options>         <dump> <pass>
/dev/mmcblk0p1   /boot                    vfat    ro                0      2
/dev/mmcblk0p2   /                        ext4    ro,noatime        0      1
/dev/mmcblk0p3   /opt/autonomous-trust    ext4    rw,noatime,nosuid 0      2
FSTAB

# Remove unnecessary files to minimize image
rm -rf "$TARGET_DIR/usr/share/man"
rm -rf "$TARGET_DIR/usr/share/doc"
rm -rf "$TARGET_DIR/usr/share/locale"

echo "[post-build] Done"
