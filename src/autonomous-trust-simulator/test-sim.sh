#!/bin/sh

pytest tests/test_metrics_collector.py tests/test_appalachian_compose.py -v
pytest tests/test_appalachian_inprocess.py -v

# FIXME these are failing because AT is not running correctly
config/test-simulation.sh --hilltop-only
config/test-simulation.sh
