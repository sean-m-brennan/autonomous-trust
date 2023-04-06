#!/bin/bash

# 2023/04/06: pykraft deprecated, but KraftKit too alpha to use

# pykraft or kraftkit
tool=pykraft

# x86_64 or arm64
arch=x86_64

# linuxu or kvm or xen
platform=linuxu

# c or py or upy
impl=py


run=false
force=
clean=false
pristine=false

while [ -n "$1" ]; do
    if [ "$1" = "--tool" ]; then
	shift
	tool="$1"
    elif [ "$1" = "--arch"* ] || [ "$1" = "-m" ]; then
	shift
	arch="$1"
    elif [ "$1" = "--platform" ] || [ "$1" = "-p" ]; then
	shift
	platform="$1"
    elif [ "$1" = "--implementation" ] || [ "$1" = "-i" ]; then
	shift
	impl="$1"
    elif [ "$1" = "--run" ]; then
	run=true
    elif [ "$1" = "--force" ]; then
	force="-F"
    elif [ "$1" = "--clean" ]; then
	clean=true
    elif [ "$1" = "--pristine" ]; then
	pristine=true
    fi
    shift
done

target="autonomoustrust_$impl"
env="autonomous_trust"


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
if [ ! -f .update ] || [ $(find . -maxdepth 1 -mtime +1 -type f -name ".update" 2>/dev/null) ]; then
    if [ "$tool" = "pykraft" ]; then
	$kraft list update
    elif [ "$tool" = "kraftkit" ]; then
	$kraft pkg update
    fi
    touch .update
fi

# Build
cd $impl
if $clean; then
    $kraft clean
fi
if $pristine; then
    git clean .
fi
if [ "$tool" = "pykraft" ]; then
    cp Kraftfile kraft.yaml
    $kraft init
    $kraft configure -m $arch -p $platform -t ${target}_${platform}-$arch $force
    $kraft build
    if $run; then
	$kraft run
    fi
fi
if [ "$tool" = "kraftkit" ]; then
    $kraft build -m $arch -p $platform --log-type simple $force
    if $run; then
	$kraft run
    fi
fi
cd ..
