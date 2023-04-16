#!/bin/bash
#set -x

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
    echo "Usage: $(basename $0) [--tool TOOL] [-m|--architecture ARCH] [-p|--platform PLAT] [-i|--implementation IMPL] [--initrd] [--run] [--clean] [--pristine] [--force] [--debug] [--help]"
    echo "  where"
    echo "       TOOL is pykraft or kraftkit"
    echo "       ARCH is x86_64 or arm64 or arm"
    echo "       PLAT is kvm or linuxu or xen"
    echo "       IMPL is py or c"
}

initrdfs=false
run=false
debug=false
force=
clean=false
pristine=false
qemu_native=x86_64

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
    elif [[ "$1" = "--qemu-native" ]]; then
        shift
        qemu_native="$1"
    elif [ "$1" = "--initrd" ]; then
        initrdfs=true
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
        conda env create --file ${this_dir}/../environment.yml
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

if $pristine; then
    git clean -xdf ${this_dir}/$impl
fi
if $clean; then
    cd $this_dir/$impl && $kraft clean
    cd $working_dir
fi


# Prep libraries
if [ ! -e ${this_dir}/py/build/_sodium.c ]; then
    cd ${this_dir}
    if [ ! -d pynacl ]; then
        git clone https://github.com/pyca/pynacl.git
    fi
    cd pynacl
    PYNACL_SODIUM_STATIC=1 SODIUM_INSTALL_MINIMAL=1 python3 setup.py build &> build.log
    mkdir -p ${this_dir}/py/build
    cp "$(find . -name _sodium.c)" ${this_dir}/py/build/
    cd $working_dir
fi

libs="libffi libzmq"
for lib in $libs; do
    mkdir -p ${this_dir}/lib
    if [ ! -d ${this_dir}/lib/$lib ]; then
        cd ${this_dir}/lib && $kraft lib init --no-prompt \
            --author-name "$(git config --list | grep "user\.name" | awk -F= '{print $2}')" \
            --author-email "$(git config --list | grep "user\.email" | awk -F= '{print $2}')" \
            --origin "$(cat ${this_dir}/$lib/origin)" \
            --version "$(cat ${this_dir}/$lib/version)" $lib
        cd ${this_dir}
        cp ${this_dir}/$lib/*.uk ${this_dir}/lib/$lib/
        cp -r ${this_dir}/$lib/patch ${this_dir}/$lib/include ${this_dir}/lib/$lib/
        cd ${this_dir}/lib/$lib && git add ./* && git commit -a -m"Initial"
        rm -f ${this_dir}/.update
        $kraft list add  ${this_dir}/lib/$lib
    fi
done

# Update once a day
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
if [ ! -e $UK_WORKDIR/.patched ]; then
    cd $UK_WORKDIR && patch -p1 --forward < $this_dir/unikraft.patch
    cd $this_dir/$impl
    if [ -e $this_dir/unikraft.patch.$impl ]; then
        cd $UK_WORKDIR && patch -p1 --forward < $this_dir/unikraft.patch.$impl
        cd $this_dir/$impl
    fi
    touch $UK_WORKDIR/.patched
fi

# Build
set -e
if [ "$tool" = "pykraft" ]; then
    cp Kraftfile.9pfs kraft.yaml
    if $initrdfs; then
        cp Kraftfile.initrd kraft.yaml
    fi
    $kraft configure -m $arch -p $platform -t $kernel $force
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
    # autonomous_trust installed using Makefile.uk
    bash -c "export SODIUM_INSTALL=system && source fs0/bin/activate && fs0/bin/python3 -m ensurepip && source piprc && fs0/bin/pip3 install -r requirements.txt"
    grep -RIl "from nacl\._sodium" fs0/lib/python3.7/site-packages/nacl | xargs sed -i 's|from nacl\._sodium|from _sodium|g'
    if $initrdfs; then
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
        if $initrdfs; then
            echo "Warning: filesystem is read-only"
        fi
        echo "To exit QEMU, press ctrl-a x"
        echo qemu args: $graphics -m 1G $blkdev $initrd -kernel $kernel_path
        qemu-system-${qemu_native} $graphics -m 1G $blkdev $initrd -kernel $kernel_path
    fi
fi

cd "$working_dir" || exit 1
