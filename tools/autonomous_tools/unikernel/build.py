import os

from ..config import base_dir, ARCH
from .cfg import default_platform, default_implementation


def build_unikernel(implementation=default_implementation, platform=default_platform, debuggable=False):
    src_dir = os.path.join(base_dir, 'unikernel', implementation)

    target = 'autonomoustrust_' + implementation
    if implementation == 'c':
        target = 'autonomoustrust'

    kernel = target + '_' + platform + '-' + ARCH
    if debuggable:
        kernel += '.dbg'

    # FIXME if conda env not active, activate it

    return os.path.join(src_dir, kernel)


"""

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

"""