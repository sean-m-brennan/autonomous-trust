#!/bin/bash

this_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
network_name="at-net"
image_name="autonomous-trust"

network_type="macvlan"
mcast=false  # FIXME overlays
remote_port=2357
ipv6=
#ipv6="--ipv6"

#exclude_classes=""
exclude_classes="network"

num_nodes=2
force=
debug=
tunnel_host=
for arg in $@; do
    if [ "$arg" = "--force" ]; then
        force="--no-cache"
    elif [ "$arg" = "--help" ]; then
        echo "$(basename "$0") [--debug-build|--debug-run|--debug] [--tunnel WHO@WHERE] [--force] NUM_NODES"
        exit 0
    elif [ "$arg" = "--tunnel" ]; then
        tunnel_host=
    elif [ "$arg" = "--debug-build" ]; then
        debug="build $debug"
    elif [ "$arg" = "--debug-run" ]; then
        debug="run $debug"
    elif [ "$arg" = "--remote-debug" ]; then
        debug="remote $debug"
    elif [ "$arg" = "--debug" ]; then
        debug="build run remote"
    else
        num_nodes=$arg
    fi
done

# cleanup unused docker resources
docker images prune -f
#docker images prune -a -f --filter "until=24h"

if [ "$(docker network ls | awk '{print $2}' | grep $network_name)" = "" ]; then
    if $mcast; then
        docker swarm init
        docker network create $ipv6 --driver=weaveworks/net-plugin:latest_release --attachable $network_name
    else
        docker network create $ipv6 --driver $network_type $network_name
    fi
fi
remote_ip=$(docker network inspect ${network_name} | grep Gateway | awk '{print $NF}' | sed 's/"//g')
remote="${remote_ip}:${remote_port}"


debug_build=
debug_run=
remote_debug=false
if [[ "$debug" = *"build"* ]]; then
    debug_build="--progress=plain"
fi
if [[ "$debug" = *"run"* ]]; then
    debug_run="; exec bash"
fi
if [[ "$debug" = *"remote"* ]]; then
    remote_debug=true
fi

tunnel=
if [ "$tunnel_host" != "" ]; then
    tunnel="ssh $tunnel_host -c "
fi

docker build -t $image_name $force $debug_build "$this_dir" || exit 1

min_sec=1
max_sec=5

excludes=
for class in $exclude_classes; do
    excludes="$excludes --exclude-logs $class"
done

for n in $(seq $num_nodes); do
    remote_dbg=
    if $remote_debug && [ "$n" = "1" ]; then
      remote_dbg="--remote-debug $remote"
    fi
    extra_args="-e AUTONOMOUS_TRUST_ARGS=\"--test $remote_dbg $excludes\""
    docker_cmd="docker run --rm --name at-$n --network=$network_name $extra_args -it $image_name"
    if [ "$(which gnome-terminal)" != "" ]; then
        gnome-terminal -- sh -c "$tunnel $docker_cmd $debug_run"
    elif [ "$(which qterminal)" != "" ]; then
        qterminal -e "$tunnel $docker_cmd $debug_run"
    elif [ "$(which osascript)" != "" ]; then
        osascript -e "tell app \"Terminal\";  do script \"$tunnel $docker_cmd $debug_run\"; end tell"
    fi
    # TODO other environments
    sleep $((min_sec + RANDOM % max_sec))
done

#docker network rm $network_name
