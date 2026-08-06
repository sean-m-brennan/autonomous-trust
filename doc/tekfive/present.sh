#!/bin/bash
# ******************
#  Copyright 2023 TekFive, Inc., Sean M. Brennan, and contributors
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
# ******************

this_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
base_dir=$(cd "${this_dir}/../.." && pwd)

#$base_dir/lib/update.sh

# Enable job control
set -m

port=8888

#activate_conda autonomous_trust

echo "Starting in $base_dir"

export PYTHONPATH=${base_dir}
python3 -m autonomous_trust.inspector.viz --directory "${base_dir}"/doc/tekfive/presentation --port $port &
sim_pid=$!
sleep 1
xdg-open http://localhost:$port

job_id=$(jobs -l | grep " $sim_pid " | awk '{print $1}' | sed 's/.*\[\(.*\)\].*/\1/' )
fg "$job_id"
echo "Simulation closed"

#deactivate_conda
