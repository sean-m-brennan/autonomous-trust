#!/bin/bash

this_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
network_name="at-net"
image_name="autonomous-trust"

mcast=false

num_nodes=2
force=
debug_build=
debug_run=
for arg in $@; do
    if [ "$arg" = "--force" ]; then
        force="--no-cache"
    elif [ "$arg" = "--debug-build" ]; then
        debug_build="--progress=plain"
    elif [ "$arg" = "--debug-run" ]; then
        debug_run="; exec bash"
    elif [ "$arg" = "--debug" ]; then
        debug_build="--progress=plain"
        debug_run="; exec bash"
    else
        num_nodes=$arg
    fi
done

docker build -t $image_name $force $debug_build "$this_dir" || exit 1

if [ "$(docker network ls | grep $network_name)" = "" ]; then
    if $mcast; then
        docker swarm init
        docker network create --driver=weaveworks/net-plugin:latest_release --attachable $network_name
    else
        docker network create $network_name
    fi
fi

for n in $(seq $num_nodes); do
    docker_cmd="docker run --rm --name at-$n --network=$network_name -it $image_name"
    gnome-terminal -- sh -c "$docker_cmd $debug_run"
    # FIXME detect environments
    #osascript -e "tell app \"Terminal\";  do script \"$docker_cmd; exec bash\"; end tell"
    # TODO other environments
    sleep 0.1
done

#docker network rm $network_name
