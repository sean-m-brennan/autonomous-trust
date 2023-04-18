#! /bin/bash

env="autonomous_trust"

if [ "$(conda env list | awk '{print $1}' | grep $env)" = "" ]; then
    conda env create --file environment.yml
fi

conda_dir=$(conda info | grep -i 'base environment' | awk '{print $4}')
source "$conda_dir/etc/profile.d/conda.sh"
conda activate $env

arch=$(uname -m)
qemu_system=$(which qemu-system-$arch)
if [ "$qemu_system" = "" ]; then
    echo "Missing required qemu-system-$arch"
    exit 1
fi
#FIXME requires qemu-system-$arch, detect
unikernel/build_image.sh --run --qemu-native $arch

conda deactivate
