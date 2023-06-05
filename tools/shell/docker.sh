
build_container() {
    local image_name=$1
    local directory=$2
    local force=$3
    local debug=$4
    local file=$5

    # cleanup unused docker resources
    docker images prune
    #docker images prune --all --filter "until=24h"
    #docker system prune --all --filter "until=24h"

    debug_arg=
    if [ "$debug" != "" ]; then
	      debug_arg="--progress=plain"
    fi
    force_arg=
    if [ "$force" != "" ]; then
	      force_arg="--no-cache"
    fi
    file_arg=
    if [ "$file" != "" ]; then
        file_arg="-f $file"
    fi

    docker build -t $image_name $file_arg $force_arg $debug_arg "$directory"
}

macvlan_bridge() {
    # WARNING does not work under QubesOS
    local iface_name=${1}-bridge
    local address=$2
    local range=$3
    local device=$4

    if [ "$(ip addr show dev $iface_name)" != "" ]; then
        sudo ip link delete $iface_name
    fi
    sudo ip link add $iface_name link $device type macvlan mode bridge && \
    sudo ip addr add $address/32 dev $iface_name && \
    sudo ip link set $iface_name up && \
    sudo ip route add $range dev $iface_name
    ip a show dev $iface_name
}


create_network() {
    local net=$1  # FIXME also ipv6 version
    local network_name=$2
    local network_type=$3
    local mcast=$4
    local ipv6=$5
    local host_comms=$6

    local device=$(ip -o -4 route show to default | awk '{print $5}' | tail -n 1)
    local mask=24
    local prefix=${net%.*}

    local subnet="$net/$mask"
    local range="${prefix}.2/$((mask + 1))"  # limited to 128 containers
    local gateway="${prefix}.1"  # real router must be at this addr
    local aux="${prefix}.130"  #FIXME IPv agnostic
    local unused_addr="${prefix}.131"  # fake out docker daemon
    local iface_name=${network_name}-bridge

    if [ "$host_comms" != "" ] && [ "$network_type" = "macvlan" ]; then
        macvlan_bridge $network_name $aux $net/$((mask + 1)) $device
    elif [ "$(ip addr show dev $iface_name)" != "" ]; then
        sudo ip link delete $iface_name
    fi

    local args="--opt parent=$device --subnet $subnet --gateway $unused_addr --ip-range $range --aux-address router=$gateway"
    if [ "$ipv6" != "" ]; then
        args="$args --ipv6"
    fi
    if [ "$network_type" = "macvlan" ]; then
        args="$args -o macvlan_mode=bridge"
    fi
    if [ "$host_comms" != "" ] && [ "$network_type" = "macvlan" ]; then
        args="$args --aux-address host=${aux}"
    fi
    
    if [ "$(docker network ls | awk '{print $2}' | grep $network_name)" != "" ]; then
        docker network rm $network_name
    fi
	  if [ "$mcast" != "" ]; then
        docker swarm init
        docker network create $args --driver=weaveworks/net-plugin:latest_release --attachable $network_name
	  else
        docker network create $args --driver $network_type $network_name
	  fi
}

network_ip() {
    docker network inspect ${network_name} | grep Gateway | awk '{print $NF}' | sed 's/"//g' | sed 's/,//g'
}

run_container() {
    local container_name=$1
    local image_name=$2
    local network_name=$3
    local extra_args="$4"

    extra_args="$extra_args -e ROUTER=172.27.3.1"
    docker run --rm --name $container_name -h $container_name --cap-add NET_ADMIN --network=$network_name $extra_args -d $image_name
}

run_interactive_container() {
    local container_name=$1
    local image_name=$2
    local network_name=$3
    local extra_args="$4"
    local debug=$5
    local remote=$6
    local testing_path=$7
    local block=$8
    local blocking=false
    if [ "$block" != "" ]; then
      blocking=true
    fi

    testing_path=$(cd $testing_path && pwd)

    local debug_arg=
    if [ "$debug" != "" ]; then
	      debug_arg="; exec bash"
    fi
    local test_arg=
    if [ "$testing_path" != "" ]; then
        test_arg="-v ${testing_path}:/app"
    fi

    extra_args="$extra_args -e ROUTER=172.27.3.1"
    local docker_cmd="docker run --rm --name $container_name -h $container_name $test_arg --cap-add NET_ADMIN --network=$network_name $extra_args -it $image_name"
    echo $docker_cmd
    if [[ "$(xhost)" == *"unable to open display"* ]]; then
      echo "Cannot open container terminals; try X11 forwarding"
    fi
    if [ "$remote" != "" ] && [ "$(which xterm)" != "" ]; then
        if $blocking; then
            xterm -e /bin/sh -l -c "$docker_cmd $debug_arg"
        else
            xterm -e /bin/sh -l -c "$docker_cmd $debug_arg" &
        fi
    elif [ "$(which gnome-terminal)" != "" ]; then
        if $blocking; then
            gnome-terminal --wait -- sh -c "$docker_cmd $debug_arg"
        else
            gnome-terminal -- sh -c "$docker_cmd $debug_arg"
        fi
    elif [ "$(which qterminal)" != "" ]; then
        if $blocking; then
            qterminal -e "$docker_cmd $debug_arg"
        else
            qterminal -e "$docker_cmd $debug_arg" &
        fi
    elif [ "$(which osascript)" != "" ]; then
        if $blocking; then
            osascript -e "tell app \"Terminal\";  do script \"$docker_cmd $debug_arg\"; end tell"
        else
            osascript -e "tell app \"Terminal\";  do script \"$docker_cmd $debug_arg\"; end tell" &
        fi
    fi
    # TODO other environments
}
