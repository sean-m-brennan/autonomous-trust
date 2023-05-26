#!/bin/bash

this_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
source $this_dir/docker.sh

create_network at-net macvlan
