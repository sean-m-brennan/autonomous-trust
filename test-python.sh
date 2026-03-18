#!/bin/bash
# Run only pure Python test suites from the repo root

# Run everything relative to this script
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
cd "$here" || exit 1

export AUTONOMOUS_TRUST_BACKEND=python

extra_args="--ignore=tests/b_integration/test_two_node.py"
for pkg in autonomous-trust autonomous-trust-services autonomous-trust-inspector autonomous-trust-simulator; do
  pkg_dir="$here/src/$pkg"
  (cd "$pkg_dir" && ./run-tests.sh $extra_args $@)
done
