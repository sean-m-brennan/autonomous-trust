#!/bin/sh
# ******************
#  Copyright 2025 Sean M. Brennan and contributors
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
#
# Run simulator package tests.

# Run everything relative to the repo root
cd -- "$(dirname -- "$0")/.." || exit 1

SIM_PKG=src/autonomous-trust-simulator

usage() {
  cat <<'EOF'
Usage: test-sim-pkg.sh [OPTIONS]

Run the simulator package integration tests.

Options:
  --python      Use the Python backend (default).
  --native      Use the native backend.
  --clean       Prune before running.
  --verbose     Verbose test output.
  -h, --help    Show this help message and exit.
EOF
}

backend=python
verbose=
prune=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --native)
            backend=
            shift
            ;;
        --python)
            backend=python
            shift
            ;;
        --clean)
            prune=true
            shift
            ;;
        --verbose)
            verbose="-v"
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
    esac
done

if [ -n "$backend" ]; then
  test_flag="--backend $backend"
  sim_flag="--${backend}"
fi

pytest $SIM_PKG/tests/b_integration/test_metrics_collector.py \
       $SIM_PKG/tests/b_integration/test_appalachian_compose.py \
       $SIM_PKG/tests/b_integration/test_appalachian_inprocess.py $verbose $test_flag

echo "---------- Test simulator scenario ----------"
if $prune; then
  docker system prune -f
fi
sim_out=$($SIM_PKG/config/test-simulation-scenarios.sh $sim_flag --quick 2>/dev/null)
sim_metrics=$(echo "$sim_out" | grep "[PASSED]" | wc -l)
if [ -n "$verbose" ]; then
  echo "$sim_out" | grep "[PASSED]\|[FAILED]"
fi
if [ "$sim_metrics" -lt "3" ]; then
  echo "Simulation FAILED:"
  echo "$sim_out" | grep "[FAILED]"
  exit 1
else
  echo "Simulation PASSED baseline criteria"
fi
