#! /bin/bash

# Enable job control
set -m

src_file=../../viz/simulate.py

env="autonomous_trust"
port=8888

if [ $(conda env list | awk '{print $1}' | grep $env) = "" ]; then
    conda env create --file autotrust.yml
fi

conda_dir=$(conda info | grep -i 'base environment' | awk '{print $4}')
source $conda_dir/etc/profile.d/conda.sh
conda activate $env

python3 $src_file --port $port &
sim_pid=$!

xdg-open http://localhost:$port

job_id=$(jobs -l | grep " $sim_pid " | awk '{print $1}' | sed 's/.*\[\(.*\)\].*/\1/' )
fg $job_id
echo "Simulation closed"
