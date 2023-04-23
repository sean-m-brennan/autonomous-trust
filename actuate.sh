#! /bin/bash

source conda/init_conda

activate_conda autonomous_trust

arch=$(uname -m)
qemu_system=$(which qemu-system-$arch)
if [ "$qemu_system" = "" ]; then
    echo "Missing required qemu-system-$arch"
    exit 1
fi
unikernel/build_image.sh --run --qemu-native $arch

#deactivate_conda
