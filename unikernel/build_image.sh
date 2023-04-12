#!/bin/bash

this_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
working_dir=$(pwd)

export UK_WORKDIR=${this_dir}/.unikraft
export KRAFTRC=${this_dir}/.kraftrc

# 2023/04/06: pykraft deprecated, but KraftKit too alpha to use

# pykraft or kraftkit
tool=pykraft

# x86_64 or arm64
arch=x86_64

# linuxu or kvm or xen
platform=kvm

# c or py or upy
impl=py

usage() {
    echo "Usage: $(basename $0) [--tool TOOL] [-m|--architecture ARCH] [-p|--platform PLAT] [-i|--implementation IMPL] [--initramfs] [--run] [--clean] [--pristine] [--force] [--debug] [--help]"
    echo "  where"
    echo "       TOOL is pykraft or kraftkit"
    echo "       ARCH is x86_64 or arm64 or arm"
    echo "       PLAT is kvm or linuxu or xen"
    echo "       IMPL is py or c"
}

initramfs=false
run=false
debug=false
force=
clean=false
pristine=false

while [ -n "$1" ]; do
    if [ "$1" = "--tool" ]; then
        shift
        tool="$1"
    elif [[ "$1" = "--arch"* ]] || [ "$1" = "-m" ]; then
        shift
        arch="$1"
    elif [ "$1" = "--platform" ] || [ "$1" = "-p" ]; then
        shift
        platform="$1"
    elif [[ "$1" = "--impl"* ]] || [ "$1" = "-i" ]; then
        shift
        impl="$1"
    elif [ "$1" = "--initramfs" ]; then
        initramfs=true
    elif [ "$1" = "--run" ]; then
        run=true
    elif [ "$1" = "--debug" ]; then
        debug=true
    elif [ "$1" = "--force" ]; then
        force="-F"
    elif [ "$1" = "--clean" ]; then
        clean=true
    elif [ "$1" = "--pristine" ]; then
        pristine=true
    elif [ "$1" = "--help" ]; then
        usage
        exit 0
    fi
    shift
done

target="autonomoustrust_$impl"
if [ "$impl" = "c" ]; then
    target=autonomoustrust
fi
env="autonomous_trust"
kernel=${target}_${platform}-$arch
if $debug; then
    kernel=$kernel.dbg
fi
kernel_path=${this_dir}/${impl}/build/$kernel

# if not already in conda env, activate it
if [ "$CONDA_PREFIX" = "" ] || [[ "$CONDA_PREFIX" != *"$env" ]]; then
    if [ "$(conda env list | awk '{print $1}' | grep $env)" = "" ]; then
        conda env create --file ../environment.yml
    fi

    conda_dir=$(conda info | grep -i 'base environment' | awk '{print $4}')
    source "$conda_dir/etc/profile.d/conda.sh"
    conda activate $env
fi

# Find existing kraft tool
kraft=
kpath_alt=$(which -a kraft | tail -n +2 | head -1)
kpath_dflt=$(which kraft)
if [ "$?" -eq "0" ]; then
    if [ "$tool" = "pykraft" ] && [[ "$kpath_dflt" = "$CONDA_PREFIX"* ]]; then
        kraft="$kpath_dflt"
    elif [ "$tool" = "kraftkit" ]; then
        if [[ "$kpath_dflt" != "$CONDA_PREFIX"* ]]; then
            kraft="$kpath_dflt"
        else
            kraft="$kpath_alt"
        fi
    fi
fi

# Install kraft, if missing
if [ "$kraft" = "" ]; then
    if [ "$tool" = "pykraft" ]; then
        # install pykraft under conda
        pip3 install git+https://github.com/unikraft/pykraft.git
    elif [ "$tool" = "kraftkit" ]; then
        # install KraftKit
        curl --proto '=https' --tlsv1.2 -sSf https://get.kraftkit.sh | sh
    fi
fi

# Update once a day
if [ ! -f .update ] || [ "$(find . -maxdepth 1 -mtime +1 -type f -name ".update" 2>/dev/null)" ]; then
    if [ "$tool" = "pykraft" ]; then
        $kraft list update
    elif [ "$tool" = "kraftkit" ]; then
        $kraft pkg update
    fi
    # FIXME use a proper patch
    if [ -e unikraft.plat.linuxu.memory.c ]; then
        cp unikraft.plat.linuxu.memory.c .unikraft/unikraft/plat/linuxu/memory.c
    fi
    touch .update
fi

# Build
cd $this_dir/$impl || exit 1
if $clean; then
    $kraft clean
fi
if $pristine; then
    git clean -xdf .
fi
set -e
if [ "$tool" = "pykraft" ]; then
    cp Kraftfile.9pfs kraft.yaml
    if $initramfs; then
        cp Kraftfile.initrd kraft.yaml
    fi
    $kraft configure -m $arch -p $platform -t $kernel $force
    $kraft build
fi
if [ "$tool" = "kraftkit" ]; then
    cp Kraftfile.9pfs Kraftfile
    if $initramfs; then
        cp Kraftfile.initrd Kraftfile
    fi
    $kraft build -m $arch -p $platform --log-type simple $force
fi
set +e

graphics="-nographic -vga none -device sga"
initrd=
blkdev=
if [ -d fs0 ]; then
    if $initramfs; then
        cd fs0 && find . | cpio -o --format=newc | gzip -9 >../initramfz && cd ..
        initrd="-initrd ${this_dir}/${impl}/initramfz"
    else
        blkdev="-fsdev local,id=myid,path=${this_dir}/${impl}/fs0,security_model=none -device virtio-9p-pci,fsdev=myid,mount_tag=fs0"
    fi
fi

if $run; then
    if [ "$platform" = "linuxu" ]; then
        $kernel_path
    elif [ "$platform" = "kvm" ]; then
        echo "To exit QEMU, press ctrl-a x"
        echo qemu args: $graphics -m 1G $blkdev $initrd -kernel $kernel_path
        qemu-system-x86_64 $graphics -m 1G $blkdev $initrd -kernel $kernel_path
    fi
fi

cd "$working_dir" || exit 1
