#!/bin/bash

this_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
src_dir=${this_dir}/../src/autonomous-trust

source ${this_dir}/docker.sh

image_name="autonomous-trust"

network_name="at-net"
network_type="macvlan"
mcast=false  # FIXME overlays
remote_port=2357
ipv6=false

#exclude_classes=""
exclude_classes="network"

num_nodes=2
force=false
debug_build=false
debug_run=false
remote_debugging=false
tunnel=false

while [ -n "$1" ]; do
    if [ "$1" = "--force" ]; then
        force=true
    elif [ "$1" = "--help" ]; then
        echo "$(basename "$0") [--debug-build|--debug-run|--debug] [--tunnel WHO@WHERE] [--force] NUM_NODES"
        exit 0
    elif [ "$1" = "--tunnel" ]; then
        tunnel=true
    elif [ "$1" = "--debug-build" ]; then
        debug_build=true
    elif [ "$1" = "--debug-run" ]; then
        debug_run=true
    elif [ "$1" = "--remote-debug" ]; then
        remote_debugging=true
    elif [ "$1" = "--debug" ]; then
      	debug_build=true
	      debug_run=true
	      remote_debugging=true
    else
        num_nodes=$1
    fi
    shift
done


#create_network 172.27.3.0 $network_name $network_type $mcast $ipv6 false
create_network 172.27.3.0 $network_name ipvlan -o ipvlan_mode=l3 $mcast $ipv6 false
remote_ip=$(network_ip)
remote="${remote_ip}:${remote_port}"


build_container $image_name "$src_dir" $force $debug_build || exit 1

min_sec=1
max_sec=5

excludes=
for class in $exclude_classes; do
    excludes="$excludes --exclude-logs $class"
done

for n in $(seq $num_nodes); do
    remote_dbg=
    if $remote_debugging && [ "$n" = "1" ]; then
        remote_dbg="--remote-debug $remote"
    fi
    extra_args="-e AUTONOMOUS_TRUST_ARGS=\"--test $remote_dbg $excludes\""

    run_interactive_container at-$n $image_name $network_name "$extra_args" $debug_run $tunnel
    sleep $((min_sec + RANDOM % max_sec))
done

#docker network rm $network_name
