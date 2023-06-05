#!/bin/bash

this_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
src_dir=${this_dir}/../src/autonomous-trust

source ${this_dir}/docker.sh

image_name="autonomous-trust"

network_name="at-net"
network_type="macvlan"
mcast=""  # FIXME overlays
remote_port=2357
ipv6=""

#exclude_classes=""
exclude_classes="network"

num_nodes=2
force=""
debug_build=""
debug_run=""
remote_debugging=""
tunnel=""
devel=""

while [ -n "$1" ]; do
    if [ "$1" = "--help" ]; then
        echo "$(basename "$0") [--debug-build|--debug-run|--debug] [--tunnel WHO@WHERE] [--force] NUM_NODES"
        exit 0
    elif [ "$1" = "--force" ]; then
        force="force"
    elif [ "$1" = "--tunnel" ]; then
        tunnel="tunnel"
    elif [ "$1" = "--devel" ]; then
        devel="-devel"
    elif [ "$1" = "--debug-build" ]; then
        debug_build="dbg_bld"
    elif [ "$1" = "--debug-run" ]; then
        debug_run="dbg_run"
    elif [ "$1" = "--remote-debug" ]; then
        remote_debugging="dbg_rmt"
    elif [ "$1" = "--debug" ]; then
      	debug_build="dbg_bld"
	      debug_run="dbg_run"
	      remote_debugging="dbg_rmt"
    else
        num_nodes=$1
    fi
    shift
done


create_network 172.27.3.0 $network_name $network_type "$mcast" "$ipv6"
remote_ip=$(network_ip)
remote="${remote_ip}:${remote_port}"

#build_container $image_name "$src_dir" $force $debug_build || exit 1

min_sec=1
max_sec=5

excludes=
for class in $exclude_classes; do
    excludes="$excludes --exclude-logs $class"
done

for n in $(seq $num_nodes); do
    remote_dbg=
    if [ "$remote_debugging" != "" ] && [ "$n" = "1" ]; then
        remote_dbg="--remote-debug $remote"
    fi
    extra_args="-e AUTONOMOUS_TRUST_ARGS=\"--live --test $remote_dbg $excludes\""

    run_interactive_container at-$n ${image_name}${devel} $network_name "$extra_args" "$debug_run" "$tunnel"
    sleep $((min_sec + RANDOM % max_sec))
done

#docker network rm $network_name
