#!/bin/bash

this_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
network_name="at-net"
image_name="autonomous-trust"

mcast=false
remote_port=2357

num_nodes=2
force=
debug=
for arg in $@; do
    if [ "$arg" = "--force" ]; then
        force="--no-cache"
    elif [ "$arg" = "--help" ]; then
        echo "$(basename "$0") [--debug-build|--debug-run|--debug] [--force] NUM_NODES"
        exit 0
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

if [ "$(docker network ls | grep $network_name)" = "" ]; then
    if $mcast; then
        docker swarm init
        docker network create --driver=weaveworks/net-plugin:latest_release --attachable $network_name
    else
        docker network create $network_name
    fi
fi
docker network ls | grep $network_name
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

docker build -t $image_name $force $debug_build "$this_dir" || exit 1

min_sec=1
max_sec=5

for n in $(seq $num_nodes); do
    if $remote_debug && [ "$n" = "1" ]; then
      remote_dbg="-e REMOTE_DEBUG_SERVER=$remote"
    fi
    docker_cmd="docker run --rm --name at-$n --network=$network_name $remote_dbg -it $image_name"
    if [ "$(which gnome-terminal)" != "" ]; then
        gnome-terminal -- sh -c "$docker_cmd $debug_run"
    elif [ "$(which qterminal)" != "" ]; then
        qterminal -e "$docker_cmd $debug_run"
    elif [ "$(which osascript)" != "" ]; then
        osascript -e "tell app \"Terminal\";  do script \"$docker_cmd $debug_run\"; end tell"
    fi
    # TODO other environments
    sleep $((min_sec + RANDOM % max_sec))
done

#docker network rm $network_name
