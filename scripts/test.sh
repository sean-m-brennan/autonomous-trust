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

Every stage runs even if an earlier one fails, and a PASS/FAIL summary for
each stage is printed at the end (so you don't have to scroll back through
the output to see whether anything failed). Exits non-zero if any stage
failed. Interrupt with Ctrl-C to stop early.

Any extra arguments are forwarded to each of the above scripts. See each
script's own --help for the options it accepts.

Options:
  -h, --help    Show this help message and exit.
EOF
}

case "${1:-}" in
  -h|--help) usage; exit 0 ;;
esac

# Run each stage, remembering its exit status. We deliberately do NOT `set -e`
# or capture/pipe the stage output: stages run live (test-integration.sh uses
# `docker run -it`, which needs a real TTY and would break behind a pipe), and
# the loop keeps going so the end-of-run summary reflects every stage.
stages=(test-packages test-c-exe test-integration test-sim-pkg)
declare -A stage_rc
overall=0

for stage in "${stages[@]}"; do
  echo
  echo "######################## ${stage}.sh ########################"
  scripts/"${stage}.sh" "$@"
  rc=$?
  stage_rc[$stage]=$rc
  if [ "$rc" -ne 0 ]; then
    overall=1
  fi
done

# ---- Final summary --------------------------------------------------------
echo
echo "============================ TEST SUMMARY ============================"
for stage in "${stages[@]}"; do
  rc=${stage_rc[$stage]}
  if [ "$rc" -eq 0 ]; then
    printf '  %-20s PASS\n' "${stage}.sh"
  else
    printf '  %-20s FAIL (exit %d)\n' "${stage}.sh" "$rc"
  fi
done
echo "====================================================================="
if [ "$overall" -eq 0 ]; then
  echo "Result: ALL STAGES PASSED"
else
  failed=""
  for stage in "${stages[@]}"; do
    [ "${stage_rc[$stage]}" -ne 0 ] && failed="$failed ${stage}.sh"
  done
  echo "Result: FAILURES in:$failed"
  echo "(scroll up to the named stage's output for the failing tests)"
fi

exit $overall
