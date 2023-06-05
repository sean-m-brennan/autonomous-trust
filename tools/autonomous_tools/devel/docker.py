def install_docker():
    # FIXME detect docker
    # download docker?
    pass


def install_multi_arch_docker():
    """
qemu_prefix=/opt/qemu-user-static

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
"""
    pass
