#!/bin/bash
#set -x  # for debugging

this_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
working_dir=$(pwd)

source ${this_dir}/../tools/conda/init_conda.sh
source ${this_dir}/get_kraft.sh
source ${this_dir}/config_libs.sh
source ${this_dir}/uk_patches/patch_uk.sh

# 2023/04/06: pykraft deprecated, but KraftKit too alpha to use

# pykraft or kraftkit
tool=pykraft

# x86_64 or arm64
arch=x86_64

# linuxu or kvm or xen
platform=kvm

# c or py or upy
impl=py

# cpus available for smp
cpu_count=$(lscpu | grep "^CPU(s)" | awk '{print $2}')


usage() {
    echo -n "Usage: $(basename $0) [--tool TOOL] [-m|--architecture ARCH] [-p|--platform PLAT] "
    echo -n "[-i|--implementation IMPL] [--smp SMP] [--initrd] [--run] [--clean] [--pristine] "
    echo "[--force] [--debug] [--help]"
    echo "  where"
    echo "       TOOL is pykraft or kraftkit"
    echo "       ARCH is x86_64 or arm64 or arm"
    echo "       PLAT is kvm or linuxu or xen"
    echo "       IMPL is py or c"
    echo "       SMP is number of cpus"
}

initrdfs=false
run=false
debug=false
force=
clean=false
pristine=false
qemu_native=x86_64

while [ -n "$1" ]; do
    if [[ "$1" = "--tool" ]]; then
        shift
        tool="$1"
    elif [[ "$1" = "--arch"* ]] || [ "$1" = "-m" ]; then
        shift
        arch="$1"
    elif [[ "$1" = "--platform" ]] || [ "$1" = "-p" ]; then
        shift
        platform="$1"
    elif [[ "$1" = "--impl"* ]] || [ "$1" = "-i" ]; then
        shift
        impl="$1"
    elif [[ "$1" = "--smp" ]]; then
        shift
        if [ "$1" -gt "0" ]; then
            cpu_count="$1"
        fi
    elif [[ "$1" = "--qemu-native" ]]; then
        shift
        qemu_native="$1"
    elif [[ "$1" = "--initrd" ]]; then
        initrdfs=true
    elif [[ "$1" = "--run" ]]; then
        run=true
    elif [[ "$1" = "--debug" ]]; then
        debug=true
    elif [[ "$1" = "--force" ]]; then
        force="-F"
    elif [[ "$1" = "--clean" ]]; then
        clean=true
    elif [[ "$1" = "--pristine" ]]; then
        pristine=true
    elif [[ "$1" = "--help" ]]; then
        usage
        exit 0
    fi
    shift
done

target="autonomoustrust_$impl"
if [ "$impl" = "c" ]; then
    target=autonomoustrust
fi
kernel=${target}_${platform}-$arch
if $debug; then
    kernel=$kernel.dbg
fi
kernel_path=${this_dir}/${impl}/build/$kernel

activate_conda autonomous_trust
kraft=$(get_kraft)

if $pristine; then
    git clean -f -f -xd ${this_dir}/$impl
fi
if $clean; then
    cd $this_dir/$impl && $kraft clean
    cd $working_dir
fi

# Prep libraries
config_ext_libs "libffi libzmq" $kraft
get_ext_sources $impl

# Update unikraft once a day
if [ ! -d ${this_dir}/.unikraft ] || [ ! -f ${this_dir}/.update ] || [ "$(find ${this_dir}/ -maxdepth 1 -mtime +1 -type f -name ".update" 2>/dev/null)" ]; then
    if [ "$tool" = "pykraft" ]; then
        $kraft list update
    elif [ "$tool" = "kraftkit" ]; then
        $kraft pkg update
    fi
    touch ${this_dir}/.update
fi

# Initialize and patch
cd $this_dir/$impl || exit 1
if [ ! -e $this_dir/$impl/.init ]; then
    $kraft init
    touch $this_dir/$impl/.init
fi
apply_uk_patches $impl

# Build
set -e
if [ "$tool" = "pykraft" ]; then
    cp Kraftfile.9pfs kraft.yaml
    if $initrdfs; then
        cp Kraftfile.initrd kraft.yaml
    fi
    # For SMP multiprocessing increase CPU count
    sed -i "s/CONFIG_UKPLAT_LCPU_MAXCOUNT=1/CONFIG_UKPLAT_LCPU_MAXCOUNT=${cpu_count}/" kraft.yaml
    echo "Configure unikraft for $impl"
    $kraft configure -m $arch -p $platform -t $kernel $force
    echo "Build unikraft for $impl"
    $kraft build
fi
if [ "$tool" = "kraftkit" ]; then
    cp Kraftfile.9pfs Kraftfile
    if $initrdfs; then
        cp Kraftfile.initrd Kraftfile
    fi
    $kraft build -m $arch -p $platform --log-type simple $force
fi
set +e

graphics="-nographic -vga none -device sga"
initrd=
blkdev=
if [ -d fs0 ]; then
    # autonomous_trust installed using Makefile.uk, but cannot do this:
    bash -c "export SODIUM_INSTALL=system && source fs0/bin/activate && fs0/bin/python3 -m ensurepip && source piprc && fs0/bin/pip3 install -r requirements.txt"
    grep -RIl "from nacl\._sodium" fs0/lib/python3.7/site-packages/nacl | xargs sed -i 's|from nacl\._sodium|from _sodium|g'
    if $initrdfs; then
        cd fs0 && find . | cpio -o --format=newc | gzip -9 >../initramfz && cd ..
        initrd="-initrd ${this_dir}/${impl}/initramfz"
    else
        blkdev="-fsdev local,id=myid,path=${this_dir}/${impl}/fs0,security_model=none -device virtio-9p-pci,fsdev=myid,mount_tag=fs0"
    fi
fi

echo "UniKraft kernel built"
echo "    kernel size $(ls -lh $kernel_path | awk '{print $5}')"
if [ -d fs0 ]; then
    echo "    filesystem size $(du -sh fs0 | awk '{print $1}')"
fi

if $run; then
    if [ "$platform" = "linuxu" ]; then
        $kernel_path
    elif [ "$platform" = "kvm" ]; then
        if $initrdfs; then
            echo "Warning: filesystem is read-only"
        fi
        echo "To exit QEMU, press ctrl-a x"
        echo qemu args: $graphics -m 1G $blkdev $initrd -kernel $kernel_path
        qemu-system-${qemu_native} $graphics -m 1G $blkdev $initrd -kernel $kernel_path
    fi
fi

cd "$working_dir" || exit 1
