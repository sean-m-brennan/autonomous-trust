#!/bin/bash

this_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
sources="autonomous-trust|${this_dir}/../src/autonomous-trust autonomous-inspector|${this_dir}/../src/autonomous-trust-inspector"

source ${this_dir}/docker.sh

force=false
# shellcheck disable=SC2199
if [[ "$@" = *"--force" ]]; then
    force=true
fi

for src_info in $sources; do
    img_name=$(echo $src_info | awk -F"|" '{print $1}' )
    path=$(echo $src_info | awk -F"|" '{print $2}' )

    echo "Build $img_name container"
    build_container $img_name $path $force false
    echo "Build ${img_name}-test container"
    build_container ${img_name}-test $path $force false ${path}/Dockerfile.test
done
