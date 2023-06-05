#!/bin/bash

## run as root

this_dir=$(cd "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
working_dir=$(pwd)


arch=$(uname -m)
kernel=$(uname -s)
case "$kernel" in
    Linux*)     os=Linux;;
    Darwin*)    os=MacOSX;;
    CYGWIN*)    machine=Cygwin;;
    MINGW*)     os=Windows;;
    *)          echo "Unknown kernel $kernel" && exit 1
esac
echo ${machine}

# Configuration
qemu_prefix=/opt/qemu-user-static
docker_subnet=172.17.1.0/24

set -e
GREEN='\033[1;32m'
RED='\033[1;31m'
NC='\033[0m' # No Color

# Download/Install conda
wget https://repo.anaconda.com/miniconda/Miniconda3-latest-${os}-${arch}.sh -O /tmp/miniconda3-latest.sh
/tmp/miniconda3-latest.sh -b -p $HOME/.miniconda3
source $HOME/.miniconda3/etc/profile.d/conda.sh && conda install -n base conda-build ninja #git
source ${this_dir}/conda/init_conda.sh
activate_conda

# Install docker
# FIXME

## Multi-arch docker
if [ ! -f "${qemu_prefix}/bin/qemu-aarch64-static" ]; then
  conda install -n base conda-build ninja #git
    echo "${GREEN}Build/install qemu-user-static${NC}"
    cd /tmp
    git clone https://gitlab.com/qemu-project/qemu.git
    cd qemu
    git submodule update --init --recursive
    mkdir build && cd build
    ../configure --prefix=${qemu_prefix} --static --disable-system --enable-linux-user
    make -j8
    make install
    cd ${qemu_prefix}/bin
    for i in *; do mv $i $i-static; done
    cd $working_dir
fi
docker run --privileged --rm tonistiigi/binfmt --install all
docker buildx create \
                --name builder \
                --driver docker-container \
                --driver-opt network=host \
                --use
docker buildx inspect builder --bootstrap


# Configure docker network (needs iproute2mac on MacOS)
device=$(ip -o -4 route show to default | awk '{print $5}' | tail -n 1)
qemu_prefix=${docker_subnet%.*}
mask=${docker_subnet#*/}
address="${qemu_prefix}.2"
range="${qemu_prefix}.3/$mask"
ip link add macvlan-bridge link $device type macvlan mode bridge && \
ip addr add $address/32 dev macvlan-bridge && \
ip link set macvlan-bridge up && \
ip route add $range dev macvlan-bridge
