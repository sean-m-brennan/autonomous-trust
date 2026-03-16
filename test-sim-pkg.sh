#!/bin/sh

SIM_PKG=src/autonomous-trust-simulator

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
        *)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
    esac
done

backend=python
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
if [ -n "verbose" ]; then
  echo "$sim_out" | grep "[PASSED]\|[FAILED]"
fi
if [ "$sim_metrics" -lt "3" ]; then
  echo "Simulation FAILED:"
  echo "$sim_out" | grep "[FAILED]"
  exit 1
else
  echo "Simulation PASSED baseline criteria"
fi
