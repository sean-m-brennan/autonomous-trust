#!/bin/bash
# ******************
#  Copyright 2026 Sean M. Brennan and contributors
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
# Run the AutonomousTrust conformance corpus.
#
# Default: Python harness only (tox -e conformance, or pytest fallback).
# Adds optional C-harness build+run plus a cross-language diff.
#
# Usage:
#   scripts/test-conformance.sh                         # Python only
#   scripts/test-conformance.sh --c                     # Python + C + diff
#   scripts/test-conformance.sh --c-only                # C only (skip Python)
#   scripts/test-conformance.sh --c --strict-coverage   # also fail on coverage gaps
#   scripts/test-conformance.sh -k secretbox            # forward args to pytest
#
# All non-flag arguments are forwarded to pytest. Flags consumed by this
# script must come before any pytest args.

set -euo pipefail

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)

run_c=0
c_only=0
strict_coverage=0
pytest_args=()

while (("$#")); do
  case "$1" in
    --c)
      run_c=1
      shift
      ;;
    --c-only)
      run_c=1
      c_only=1
      shift
      ;;
    --strict-coverage)
      strict_coverage=1
      shift
      ;;
    --)
      shift
      pytest_args+=("$@")
      break
      ;;
    *)
      pytest_args+=("$1")
      shift
      ;;
  esac
done

py_dir="$here/src/autonomous-trust"

# ---------------------------------------------------------------------------
# Python harness
# ---------------------------------------------------------------------------

run_python() {
  cd "$py_dir"
  if command -v tox >/dev/null 2>&1; then
    tox -e conformance -- "${pytest_args[@]}"
  else
    echo "tox not found; falling back to direct pytest invocation." >&2
    echo "If imports fail, install:" >&2
    echo "  pip install -r requirements.txt -r tests_require.txt jsonschema protobuf" >&2
    python -m pytest \
      conformance/harness/python \
      conformance/harness/common/tests \
      tools/tests \
      -v "${pytest_args[@]}"
  fi
}

# ---------------------------------------------------------------------------
# C harness
# ---------------------------------------------------------------------------

run_c_harness() {
  local c_dir="$here/src/c"
  local build_dir="$c_dir/build"

  if ! command -v cmake >/dev/null 2>&1; then
    echo "ERROR: cmake not found; --c requires cmake on PATH." >&2
    return 2
  fi

  rm -rf "$build_dir"
  echo "Initializing C build dir at $build_dir ..." >&2
  mkdir -p "$build_dir"
  (cd "$build_dir" && cmake ..)

  echo "Building + running C conformance harness ..."
  (cd "$build_dir" && make conformance_c)
}

# ---------------------------------------------------------------------------
# Cross-language diff
# ---------------------------------------------------------------------------

run_diff() {
  local py_result
  py_result=$(ls -1t "$py_dir"/conformance/results/python-*.json 2>/dev/null | head -n1 || true)
  if [[ -z "$py_result" ]]; then
    echo "diff: no python results JSON found under $py_dir/conformance/results/" >&2
    echo "diff: skipping (run without --c-only first to produce one)." >&2
    return 0
  fi

  local c_result="$here/src/c/build/conformance/results/c-latest.json"
  if [[ ! -f "$c_result" ]]; then
    echo "diff: C results not at $c_result; skipping." >&2
    return 0
  fi

  echo
  echo "Cross-language diff: python vs c"

  cd "$py_dir"
  local diff_args=("$py_result" "$c_result")
  if (( strict_coverage )); then
    diff_args+=(--strict-coverage)
  fi
  python -m conformance.harness.common.diff_results "${diff_args[@]}"
}

# ---------------------------------------------------------------------------
# Drive
# ---------------------------------------------------------------------------

if (( ! c_only )); then
  run_python
fi

if (( run_c )); then
  run_c_harness
  run_diff
fi
