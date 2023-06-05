#!/bin/bash

this_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
source $this_dir/docker.sh

# shellcheck disable=SC2199
if [[ "$@" == *"--host"* ]]; then
    create_network at-net macvlan "" "" "host"
else
    create_network at-net macvlan
fi
