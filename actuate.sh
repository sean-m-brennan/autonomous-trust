#!/bin/bash

this_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
num_nodes=${1:-1}
network_name="at-net"
image_name="autonomous-trust"

docker build -t $image_name "$this_dir" || exit 1

if [ "$(docker network ls | grep $network_name)" = "" ]; then
    docker network create $network_name
fi

for n in seq $num_nodes; do
    docker_cmd="docker run -it -d $image_name $n"
    gnome-terminal -- sh -c "$docker_cmd; exec bash"
    # FIXME detect environments
    #osascript -e "tell app \"Terminal\";  do script \"$docker_cmd; exec bash\"; end tell"
    # TODO other environments
done

#docker network rm $network_name
