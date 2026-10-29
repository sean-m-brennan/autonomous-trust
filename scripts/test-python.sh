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
# Run every package even after a failure, then exit non-zero if any failed.
# The loop used to discard each status, so the script exited 0 on failures.
failed=()
for pkg in autonomous-trust autonomous-trust-oracle autonomous-trust-zta autonomous-trust-rendezvous autonomous-trust-first-contact autonomous-trust-dtn autonomous-trust-services autonomous-trust-inspector autonomous-trust-evaluation autonomous-trust-simulator autonomous-trust-operator; do
  pkg_dir="$here/src/$pkg"
  rc=0
  (cd "$pkg_dir" && ./run-tests.sh $extra_args "$@") || rc=$?
  if [ "$rc" -ne 0 ]; then
    failed+=("$pkg (exit $rc)")
  fi
done

if [ "${#failed[@]}" -ne 0 ]; then
  echo
  echo "test-python.sh: ${#failed[@]} package(s) failed:"
  printf '  %s\n' "${failed[@]}"
  exit 1
fi
