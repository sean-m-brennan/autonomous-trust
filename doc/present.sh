#!/bin/bash

this_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
base_dir=$(cd "${this_dir}/.." && pwd)

$base_dir/lib/update.sh

# Enable job control
set -m

port=8888

#activate_conda autonomous_trust

export PYTHONPATH=${base_dir}
python3 -m autonomous_trust.inspector.viz --directory "${base_dir}"/doc/presentation --port $port &
sim_pid=$!
sleep 1
xdg-open http://localhost:$port

job_id=$(jobs -l | grep " $sim_pid " | awk '{print $1}' | sed 's/.*\[\(.*\)\].*/\1/' )
fg "$job_id"
echo "Simulation closed"

#deactivate_conda
