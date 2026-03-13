#!/bin/sh

#backend=
backend=python
if [ -n "$backend" ]; then
  test_flag="--backend $backend"
  sim_flag="--${backend}"
fi

pytest tests/b_integration/test_metrics_collector.py \
       tests/b_integration/test_appalachian_compose.py \
       tests/b_integration/test_appalachian_inprocess.py -v $test_flag

# FIXME these are failing because AT is not running correctly
config/test-simulation.sh $sim_flag --quick --output sim-result.json
# FIXME evaluate json
