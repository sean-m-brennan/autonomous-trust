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
# Run the AutonomousTrust conformance corpus.
#
# Default: Python harness only (tox -e conformance, or pytest fallback).
# Adds optional C-harness build+run plus a cross-language diff.
#
# Usage:
#   scripts/test-conformance.sh                         # Python + C + diff
#   scripts/test-conformance.sh --python                # Python only (skip C)
#   scripts/test-conformance.sh --c                     # C only (skip Python)
#   scripts/test-conformance.sh --strict-coverage       # also fail on coverage gaps
#   scripts/test-conformance.sh -k secretbox            # forward args to pytest
#
# All non-flag arguments are forwarded to pytest. Flags consumed by this
# script must come before any pytest args.

set -euo pipefail

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)

usage() {
  cat <<'EOF'
Usage: test-conformance.sh [OPTIONS] [pytest args...]

Run the AutonomousTrust conformance corpus. By default runs the Python harness,
the C harness, and a cross-language diff.

Options:
  --c                 C harness only (skip Python).
  --python            Python harness only (skip C).
  --strict-coverage   Also fail on coverage gaps.
  -h, --help          Show this help message and exit.

All non-flag arguments are forwarded to pytest. Flags consumed by this script
must come before any pytest args; use '--' to force everything after it to
pytest.
EOF
}

run_c=1
c_only=0
strict_coverage=0
pytest_args=()

while (("$#")); do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --c)
      run_c=1
      c_only=1
      shift
      ;;
    --python)
      run_c=0
      c_only=0
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
  # Prefer tox unless the caller opts out. Set CONFORMANCE_SKIP_TOX=1 when the
  # project conda env (config/cfg/environment.yml + devel_environ.yml) is
  # already active and IS the environment under test — tox would otherwise
  # spin up an isolated venv and pip-reinstall everything, bypassing conda
  # (and re-introducing the pip path conda is meant to replace). The GitHub
  # conformance workflow sets this so the harness runs in the conda interpreter.
  if [[ -z "${CONFORMANCE_SKIP_TOX:-}" ]] && command -v tox >/dev/null 2>&1; then
    tox -e conformance -- "${pytest_args[@]}"
  else
    if [[ -n "${CONFORMANCE_SKIP_TOX:-}" ]]; then
      echo "CONFORMANCE_SKIP_TOX set; running pytest directly in the active env." >&2
    else
      echo "tox not found; falling back to direct pytest invocation." >&2
    fi
    echo "If imports fail, activate the project conda env (which supplies" >&2
    echo "protobuf and the harness deps):" >&2
    echo "  conda activate autonomous_trust" >&2
    echo "  conda install -c conda-forge jsonschema   # if missing" >&2
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

# Build dir the C conformance harness was run in; consumed by run_diff to
# locate c-latest.json. Set by run_c_harness once it picks ZTA-on vs -off.
c_build_dir=""

run_c_harness() {
  local c_dir="$here/src/c"

  if ! command -v cmake >/dev/null 2>&1; then
    echo "ERROR: cmake not found; --c requires cmake on PATH." >&2
    return 2
  fi

  # ZTA: pin the zta-x509-*/zta-ddil-defer scenarios symmetrically (they run
  # on the C side only under AT_ZTA, which needs OpenSSL). When OpenSSL is
  # present, build with -DAT_ZTA=ON in a dedicated build-zta/ dir so the
  # plain build/ stays ZTA-free for dev/ctest. Without OpenSSL, fall back to
  # build/ with AT_ZTA off — those scenarios then skip on C, which is still
  # non-asymmetric (diff_results treats a one-side skip as a match), just
  # unpinned on this side.
  local cmake_zta_arg=""
  local build_dir
  if pkg-config --exists openssl 2>/dev/null \
     || [[ -f /usr/include/openssl/ssl.h ]]; then
    build_dir="$c_dir/build-zta"
    cmake_zta_arg="-DAT_ZTA=ON"
  else
    echo "OpenSSL not found; building C conformance without AT_ZTA " \
         "(zta-x509-* scenarios will skip on the C side)." >&2
    build_dir="$c_dir/build"
  fi
  c_build_dir="$build_dir"

  # Cache-staleness guard: if any FILEPATH the cache thinks it knows is
  # missing on disk now (e.g. a system lib was uninstalled, or a conda
  # env activation since last build moved the library to a new prefix),
  # cmake will keep using the stale path and `make` will fail with a
  # cryptic "No rule to make target /old/path/libfoo.so".  Wipe the
  # build dir in that case so cmake re-resolves from scratch.
  if [[ -f "$build_dir/CMakeCache.txt" ]]; then
    local stale=""
    while IFS= read -r p; do
      if [[ -n "$p" && ! -e "$p" ]]; then
        stale="$p"
        break
      fi
    done < <(grep -E "^[A-Za-z_]+_(LIBRARY|EXECUTABLE|INCLUDE_DIR):(FILEPATH|PATH)=/" \
                "$build_dir/CMakeCache.txt" \
             | sed -E 's/^[^=]+=//' | grep -v NOTFOUND)
    if [[ -n "$stale" ]]; then
      echo "Cache references missing path: $stale" >&2
      echo "Wiping $build_dir to force a clean reconfigure ..." >&2
      rm -rf "$build_dir"
    fi
  fi

  if [[ ! -d "$build_dir" ]]; then
    echo "Initializing C build dir at $build_dir ..." >&2
    mkdir -p "$build_dir"
    (cd "$build_dir" && cmake .. $cmake_zta_arg)
  else
    # Reuse existing build dir for incremental builds. The compiler launcher
    # set up by AT_CC_VALIDATE_OUTPUT (see src/c/CMakeLists.txt) handles the
    # virtiofs page-cache reconciliation hazard that previously forced us
    # to wipe build/ on every run; refresh the cmake config in case CMake
    # files changed since last run (and to apply/keep -DAT_ZTA).
    (cd "$build_dir" && cmake .. $cmake_zta_arg) >/dev/null
  fi

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

  local c_result="${c_build_dir:-$here/src/c/build}/conformance/results/c-latest.json"
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
#
# Each harness and the diff run to completion independently: a harness that
# reports failing cases (or a C build/run that exits nonzero) must NOT abort the
# script before the cross-language diff prints its verdict. Both harnesses still
# write their results JSON on the way out (pytest via teardown_module, the C
# runner unconditionally), so the diff always has something to compare. We
# capture each step's exit code and fold them into the final status, so CI stays
# strict (nonzero on ANY harness failure OR asymmetry) while the
# "N asymmetric" line is always visible.

py_rc=0
c_rc=0
diff_rc=0

if (( ! c_only )); then
  set +e
  run_python
  py_rc=$?
  set -e
  (( py_rc != 0 )) && echo "note: python harness reported failing/errored cases (rc=$py_rc)." >&2
fi

if (( run_c )); then
  set +e
  run_c_harness
  c_rc=$?
  set -e
  (( c_rc != 0 )) && echo "note: C harness reported failing/errored cases (rc=$c_rc)." >&2

  set +e
  run_diff
  diff_rc=$?
  set -e
fi

echo
echo "==== conformance summary ===="
(( ! c_only )) && echo "  python harness : rc=$py_rc"
if (( run_c )); then
  echo "  c harness      : rc=$c_rc"
  echo "  asymmetry diff : rc=$diff_rc   (0 = 0 asymmetric pass/fail)"
fi
if (( py_rc != 0 || c_rc != 0 )); then
  echo "  NOTE: a harness had failing cases; 'asymmetry diff rc=0' means the two" >&2
  echo "        sides AGREE per case, NOT that every case passed. Check the rc"  >&2
  echo "        lines above for actual pass/fail." >&2
fi

# Fail on any harness failure OR a true cross-language asymmetry.
if (( py_rc != 0 || c_rc != 0 || diff_rc != 0 )); then
  exit 1
fi
exit 0
