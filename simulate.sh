#! /bin/bash

source conda/init_conda

# Enable job control
set -m

src_file=autonomous_trust/viz/__main__.py
port=$(grep "default_port =" $src_file | awk '{print $3}')

activate_conda autonomous_trust

python3 -m autonomous_trust.viz &
sim_pid=$!
sleep 1
xdg-open "http://localhost:$port"

job_id=$(jobs -l | grep " $sim_pid " | awk '{print $1}' | sed 's/.*\[\(.*\)\].*/\1/' )
fg "$job_id"
echo "Simulation closed"

#deactivate_conda
