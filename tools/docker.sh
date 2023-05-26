
build_container() {
    image_name=$1
    directory=$2
    force=${3:-false}
    debug=${4:-false}
    file=$5

    # cleanup unused docker resources
    docker images prune
    #docker images prune --all --filter "until=24h"
    #docker system prune --all --filter "until=24h"

    debug_arg=
    if $debug; then
	      debug_arg="--progress=plain"
    fi
    force_arg=
    if $force; then
	      force_arg="--no-cache"
    fi
    file_arg=
    if [ "$file" != "" ]; then
        file_arg="-f $file"
    fi

    docker build -t $image_name $file_arg $force_arg $debug_arg "$directory" || exit 1
}

macvlan_bridge() {
    iface_name=${1}-bridge
    address=$2
    range=$3
    device=$4
    set -x #FIXME

    if [ "$(ip addr show dev $iface_name)" != "" ]; then
      sudo ip link delete $iface_name
    fi
    sudo ip link add $iface_name link $device type macvlan mode bridge && \
    sudo ip addr add $address/32 dev $iface_name && \
    sudo ip link set $iface_name up && \
    sudo ip route add $range dev $iface_name
}


create_network() {
    network_name=$1
    network_type=$2
    mcast=${3:-false}
    ipv6=$4
    host_comms=${5:-false}
    net="172.27.3.0"  #FIXME from args, also ipv6 version

    device=$(ip -o -4 route show to default | awk '{print $5}')
    mask=24
    prefix=${net%.*}

    subnet="$net/$mask"
    range="${prefix}.2/$((mask + 1))"  # limited to 128 containers
    gateway="${prefix}.1"
    aux="${prefix}.130"  #FIXME IPv agnostic

    if $host_comms; then
        macvlan_bridge $network_name $aux $net/$((mask + 1)) $device
    fi

    args="--opt parent=$device $ipv6 --subnet $subnet --gateway $gateway --ip-range $range"
    if [ "$network_type" = "macvlan" ]; then
        args="$args --aux-address host=${aux}"
    fi
    
    if [ "$(docker network ls | awk '{print $2}' | grep $network_name)" != "" ]; then
        docker network rm $network_name
    fi
	  if $mcast; then
        docker swarm init
        docker network create $args --driver=weaveworks/net-plugin:latest_release --attachable $network_name
	  else
        docker network create $args --driver $network_type $network_name
	  fi
}

network_ip() {
    docker network inspect ${network_name} | grep Gateway | awk '{print $NF}' | sed 's/"//g'
}

run_container() {
    container_name=$1
    image_name=$2
    network_name=$3
    extra_args=$4
    remote_host=$5
    debug=${6:-false}

    tunnel=
    if [ "$remote_host" != "" ]; then
	      tunnel="ssh $remote_host -c "
    fi
    debug_arg=
    if $debug; then
	      debug_arg="; exec bash"
    fi

    docker_cmd="docker run --rm --name $container_name --network=$network_name $extra_args -it $image_name"
    if [ "$(which gnome-terminal)" != "" ]; then
        gnome-terminal -- sh -c "$tunnel $docker_cmd $debug_arg"
    elif [ "$(which qterminal)" != "" ]; then
        qterminal -e "$tunnel $docker_cmd $debug_arg"
    elif [ "$(which osascript)" != "" ]; then
        osascript -e "tell app \"Terminal\";  do script \"$tunnel $docker_cmd $debug_arg\"; end tell"
    fi
    # TODO other environments
}
