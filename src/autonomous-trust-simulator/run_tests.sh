#!/bin/bash
cd "$(dirname "$0")"
python -m pytest --ignore=tests/local -q \
  --cov=autonomous_trust --cov-config=.coveragerc --cov-report=term-missing \
  tests/a_unit/ tests/b_integration/ tests/c_system "$@"
