#!/bin/bash

this_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
num_nodes=${1:-2}
network_name="at-net"
image_name="autonomous-trust"

force=
debug_build=
debug_run=
if [[ "$@" = *"--force"* ]]; then
    force="--no-cache"
fi
if [[ "$@" = *"--debug-build"* ]]; then
    debug_build="--progress=plain"
fi
if [[ "$@" = *"--debug-run"* ]]; then
    debug_run="; exec bash"
fi

docker build -t $image_name $force $debug_build "$this_dir" || exit 1

if [ "$(docker network ls | grep $network_name)" = "" ]; then
    docker network create $network_name
fi

for n in $(seq $num_nodes); do
    docker_cmd="docker run --rm --name at-$n --network=$network_name -it $image_name"
    gnome-terminal -- sh -c "$docker_cmd $debug_run"
    # FIXME detect environments
    #osascript -e "tell app \"Terminal\";  do script \"$docker_cmd; exec bash\"; end tell"
    # TODO other environments
done

#docker network rm $network_name
