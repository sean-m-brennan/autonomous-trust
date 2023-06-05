#!/bin/bash

num_containers=4

this_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
sources="autonomous-trust|${this_dir}/../src/autonomous-trust autonomous-inspector|${this_dir}/../src/autonomous-trust-inspector"

source ${this_dir}/docker.sh

debug=""
tunnel=""
# shellcheck disable=SC2199
if [[ "$@" = *"--debug"* ]]; then
    debug="debug"
fi
# shellcheck disable=SC2199
if [[ "$@" = *"--tunnel"* ]]; then
    tunnel="tunnel"
fi

for src_info in $sources; do
    img_name=$(echo $src_info | awk -F"|" '{print $1}' )
    path=$(echo $src_info | awk -F"|" '{print $2}' )

    echo
    echo "Build $img_name container"
    build_container $img_name $path
    echo
    echo "Build ${img_name}-test container"
    build_container ${img_name}-test $path "" "" ${path}/Dockerfile.test
done

network_name="at-net"
network_type="macvlan"
create_network 172.27.3.0 $network_name $network_type

min_sec=1
max_sec=5
for src_info in $sources; do
    path=$(echo $src_info | awk -F"|" '{print $2}' )
    containers=""

    for n in $(seq $num_containers); do
        containers="$containers at-$n"
        run_container at-$n autonomous-trust at-net
        ip=$(docker inspect --format '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' at-$n)
        echo "$ip" >> ${path}/docker_ips
        sleep $((min_sec + RANDOM % max_sec))
    done
    sleep 1
    run_interactive_container at-test autonomous-trust-test at-net "" "$debug" "$tunnel" "$path" "block"

    docker stop $containers
    rm ${path}/docker_ips
    exit  #FIXME
done
