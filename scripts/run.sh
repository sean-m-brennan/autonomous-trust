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
# Build a python distribution for live use

# Run everything relative to the repo root
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$here" || exit 1

usage() {
  cat <<'EOF'
Usage: run.sh <target> [extra args...] [-h|--help]

Top-level run dispatcher. Extra arguments are forwarded to the underlying
run script.

Targets:
  c-demo     Run the demo with the C variant (run-demo.sh --variant=c).
  demo       Run the demo (run-demo.sh).
  mission    Run the mission (run-mission.sh).
  operator   Run the operator console TUI (run-operator.sh).

Pass --help to the underlying script (e.g. 'run.sh demo --help') for its
target-specific options.

Options:
  -h, --help    Show this help message and exit.
EOF
}

case "${1:-}" in
  -h|--help|"") usage; [ -z "${1:-}" ] && exit 1 || exit 0 ;;
esac

WHAT=$1  # required
shift

if [ "$WHAT" = "c-demo" ]; then
  scripts/run-demo.sh --variant=c $@
elif [ "$WHAT" = "demo" ]; then
  scripts/run-demo.sh $@
elif [ "$WHAT" = "mission" ]; then
  scripts/run-mission.sh $@
elif [ "$WHAT" = "operator" ]; then
  scripts/run-operator.sh $@
fi
