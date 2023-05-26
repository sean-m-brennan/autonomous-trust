#!/bin/bash

this_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
src_dir=${this_dir}/../src/autonomous-trust

source ${src_dir}/conda/init_conda

activate_conda autonomous_trust

arch=$(uname -m)
qemu_system=$(which qemu-system-$arch)
if [ "$qemu_system" = "" ]; then
    echo "Missing required qemu-system-$arch"
    exit 1
fi
${this_dir}/../unikernel/build_image.sh --run --qemu-native $arch

#deactivate_conda
