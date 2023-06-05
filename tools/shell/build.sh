#!/bin/bash

this_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
sources="autonomous-trust|${this_dir}/../src/autonomous-trust autonomous-inspector|${this_dir}/../src/autonomous-trust-inspector"
base_dir=$(cd "$this_dir/.." && pwd)
src_dir=$base_dir/src
dist_dir=$src_dir/dist

force=""
# shellcheck disable=SC2199
if [[ "$@" = *"--force" ]]; then
    force="--no-cache"
fi
skip_pkg=""
# shellcheck disable=SC2199
if [[ "$@" = *"--skip-pkg" ]]; then
    skip_pkg="skip"
fi

set -e

#platforms="linux/amd64,linux/arm64"
platforms="linux/amd64"
echo "Build package-builder containers"
# FIXME buildx needs troubleshooting
#docker buildx build $force --platform $platforms --tag package-builder -f ${src_dir}/Dockerfile-build ${src_dir}
docker build $force -t package-builder -f ${src_dir}/Dockerfile-build ${src_dir}

if [ "$skip_pkg" = "" ]; then
    for src_info in $sources; do
        img_name=$(echo $src_info | awk -F"|" '{print $1}')
        path=$(echo $src_info | awk -F"|" '{print $2}')
        path=$(cd $path && pwd)

        # FIXME buildx image naming
        for platform in $platforms; do
            pkg_name=${img_name/-/_}
            arch=${platform#*/}
            img_arch_name=$img_name # -$arch (from $platform)
            do_build=false
            img_status=$(docker images | awk '{print $1}' | grep ^$img_arch_name$)
            if [ "$img_status" = "" ]; then
                do_build=true
            else
                pkg_time=$(find ${dist_dir}/?* -name "${pkg_name}-*.tar.bz2" -printf "%T+%Tz\n" | sort -k 1 | tail -1 | awk '{print $1}')
                src_time=$(find ${path}/?* -type f -printf "%T+%Tz\n" | sort | tail -1)
                if [[ "$pkg_time" < "$src_time" ]]; then
                    do_build=true
                fi
            fi
            if $do_build; then
                echo "Create $img_name package"
                docker run --rm -u $(id -u):$(id -g) -v ${path}:/build/src -v ${dist_dir}:/build/dist -it package-builder
            fi
        done
    done
fi

for src_info in $sources; do
    img_name=$(echo $src_info | awk -F"|" '{print $1}' )
    path=$(echo $src_info | awk -F"|" '{print $2}' )
    path=$(cd $path && pwd)

    echo
    echo "Build $img_name container"
    docker build $force -t $img_name -f $path/Dockerfile $src_dir
    echo
    echo "Build $img_name-devel container"
    docker build $force -t $img_name-devel -f $path/Dockerfile-devel $base_dir
    echo
    echo "Build ${img_name}-test container"
    docker build $force -t $img_name-test -f $path/Dockerfile-test $path
done
