#!/bin/bash
# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
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
# Test the code base
set -e

# Run everything relative to the repo root
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$here" || exit 1

usage() {
  cat <<'EOF'
Usage: test.sh [extra args...] [-h|--help]

Run the full test suite for the code base, in order:
  - test-packages.sh    (Python package tests)
  - test-c-exe.sh       (C test suites)
  - test-integration.sh (multi-node Docker integration tests)
  - test-sim-pkg.sh     (simulator package tests)

Any extra arguments are forwarded to each of the above scripts. See each
script's own --help for the options it accepts.

Options:
  -h, --help    Show this help message and exit.
EOF
}

case "${1:-}" in
  -h|--help) usage; exit 0 ;;
esac

scripts/test-packages.sh $@
scripts/test-c-exe.sh $@
scripts/test-integration.sh $@
scripts/test-sim-pkg.sh $@
