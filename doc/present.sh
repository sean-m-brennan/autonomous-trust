#!/bin/bash

this_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
src_dir=${this_dir}/../src

source ${src_dir}/trust/conda/init_conda

# Enable job control
set -m

port=8888

activate_conda autonomous_trust

export PYTHONPATH=${src_dir}/inspector
python3 -m autonomous_inspector.viz --directory "$PWD"/doc/presentation --port $port &
sim_pid=$!
sleep 1
xdg-open http://localhost:$port

job_id=$(jobs -l | grep " $sim_pid " | awk '{print $1}' | sed 's/.*\[\(.*\)\].*/\1/' )
fg "$job_id"
echo "Simulation closed"

#deactivate_conda
