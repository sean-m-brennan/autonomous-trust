#!/bin/bash
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
# Run only pure Python test suites from the repo root.

# Run everything relative to the repo root
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$here" || exit 1

usage() {
  cat <<'EOF'
Usage: test-python.sh [pytest args...] [-h|--help]

Run only the pure-Python test suites (AUTONOMOUS_TRUST_BACKEND=python) for
every autonomous-trust package via each package's run-tests.sh. The two-node
integration test is ignored by default.

Any extra arguments are forwarded to run-tests.sh / pytest.

Options:
  -h, --help    Show this help message and exit.
EOF
}

case "${1:-}" in
  -h|--help) usage; exit 0 ;;
esac

export AUTONOMOUS_TRUST_BACKEND=python

extra_args="--ignore=tests/b_integration/test_two_node.py"
for pkg in autonomous-trust autonomous-trust-services autonomous-trust-inspector autonomous-trust-evaluation autonomous-trust-simulator autonomous-trust-operator; do
  pkg_dir="$here/src/$pkg"
  (cd "$pkg_dir" && ./run-tests.sh $extra_args $@)
done
