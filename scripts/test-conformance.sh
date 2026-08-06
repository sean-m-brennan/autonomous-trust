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
  --no-clean          Reuse the C build dir incrementally instead of wiping it
                      first. Faster, but see the corruption note below.
  -h, --help          Show this help message and exit.

Environment:
  AT_CONFORMANCE_BUILD_DIR   Where to build the C harness. Default is
                             src/c/build-zta (or src/c/build without OpenSSL).
                             Point this at a non-virtiofs filesystem -- e.g.
                             /tmp/at-conformance-build -- to avoid the object
                             corruption described below. The results JSON is read
                             from whichever directory is used, so overriding this
                             keeps the cross-language diff consistent.
  CONFORMANCE_NO_CLEAN=1     Same as --no-clean.
  CONFORMANCE_SKIP_TOX=1     Run pytest directly in the active env, no tox.

Why the C build dir is wiped by default: on this VM's virtiofs-backed repo mount,
gcc intermittently writes objects whose ELF is structurally valid but whose symbol
table is wrong -- measured twice in one sitting, as `capabilities.c.o` defining a
symbol ABSOLUTE at 0 instead of in .text, and `adapters/network.c.o` carrying no
symbols at all. Both surfaced only as a confusing link failure naming an innocent
file, and AT_CC_VALIDATE_OUTPUT's launcher did NOT catch either (it flagged a
different object in the same run). Incremental builds keep such an object forever,
so the default is to start clean; use --no-clean when iterating and you are
prepared to diagnose a bad object by hand (nm the archive for the symbol the linker
calls missing).

Why the cross-language diff can refuse to run: the python side is read from the
newest src/autonomous-trust/conformance/results/python-*.json, and that directory
keeps every historical result. If the python harness dies before writing its JSON
(a missing dep or a pytest collection error will do it), the newest file is a
PREVIOUS run's -- and diffing against it prints "0 asymmetric", which reads as
cross-language agreement from a run that never happened. Measured 2026-08-06
against a file 44 minutes old. So when the python harness runs, its results must
be newer than the run; otherwise the diff refuses and the summary says symmetry is
UNKNOWN rather than confirmed. With --c the python harness is deliberately skipped,
so a previous run's file is accepted and its age is printed.

All non-flag arguments are forwarded to pytest. Flags consumed by this script
must come before any pytest args; use '--' to force everything after it to
pytest.
EOF
}

run_c=1
c_only=0
strict_coverage=0
# Wipe the C build dir before building. Default ON; see the usage text for the
# virtiofs object-corruption measurement that justifies it.
clean_build=${CONFORMANCE_NO_CLEAN:+0}
clean_build=${clean_build:-1}
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
    --no-clean)
      clean_build=0
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

# Touched immediately before the Python harness runs, so run_diff can tell a
# results JSON this invocation produced from one left behind by an earlier run.
# Empty when the Python harness was skipped (--c). See run_diff.
py_run_marker=""
cleanup_marker() { [[ -n "$py_run_marker" ]] && rm -f "$py_run_marker"; return 0; }
trap cleanup_marker EXIT

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
  local have_openssl=0
  if pkg-config --exists openssl 2>/dev/null \
     || [[ -f /usr/include/openssl/ssl.h ]]; then
    have_openssl=1
    cmake_zta_arg="-DAT_ZTA=ON"
  else
    echo "OpenSSL not found; building C conformance without AT_ZTA " \
         "(zta-x509-* scenarios will skip on the C side)." >&2
  fi

  # AT_CONFORMANCE_BUILD_DIR relocates the build, most usefully OFF the
  # virtiofs repo mount (see the corruption note in --help). The ZTA decision
  # above is independent of WHERE we build, so an override still gets
  # -DAT_ZTA=ON when OpenSSL is available -- otherwise pointing the build
  # elsewhere would silently drop the zta-* pins.
  if [[ -n "${AT_CONFORMANCE_BUILD_DIR:-}" ]]; then
    build_dir="$AT_CONFORMANCE_BUILD_DIR"
    # Absolute, because the build is driven from inside the directory and a
    # relative path would resolve against the wrong cwd.
    mkdir -p "$build_dir"
    build_dir=$(cd -- "$build_dir" && pwd)
    echo "Using C build dir from AT_CONFORMANCE_BUILD_DIR: $build_dir" >&2
  elif (( have_openssl )); then
    build_dir="$c_dir/build-zta"
  else
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

  # Clean before build, by default.
  #
  # This used to reuse the build dir unconditionally, on the reasoning that the
  # AT_CC_VALIDATE_OUTPUT compiler launcher (src/c/CMakeLists.txt) handles the
  # virtiofs write hazard that had previously forced a wipe every run. Measured
  # 2026-08-06: it does not handle every shape. Two runs in one sitting linked
  # against objects whose ELF was structurally valid but whose symbol table was
  # not -- `capabilities.c.o` defining find_capability ABSOLUTE at 0 rather than
  # in .text, and `adapters/network.c.o` with no symbols at all, so
  # at_network_run came out undefined. The launcher flagged a THIRD file
  # (logger.c.o) in the same run and passed both of those. An incremental build
  # keeps such an object indefinitely, and the failure presents as a link error
  # naming an innocent file, which is expensive to diagnose. Starting clean costs
  # a full compile and removes the whole class.
  #
  # --no-clean / CONFORMANCE_NO_CLEAN=1 opts out for fast iteration. If you use
  # it and hit "undefined reference" or "relocation against absolute symbol",
  # suspect a corrupt object before suspecting the code: nm the ARCHIVE for the
  # symbol, delete the offending .o plus lib*.a, and rebuild.
  if (( clean_build )) && [[ -d "$build_dir" ]]; then
    echo "Wiping $build_dir for a clean build (--no-clean to reuse) ..." >&2
    rm -rf "$build_dir"
  fi

  if [[ ! -d "$build_dir" ]]; then
    echo "Initializing C build dir at $build_dir ..." >&2
    mkdir -p "$build_dir"
    # -S/-B rather than `cd $build_dir && cmake ..`: with
    # AT_CONFORMANCE_BUILD_DIR pointing outside the source tree, ".." is not the
    # source dir and cmake would configure whatever happens to be there.
    cmake -S "$c_dir" -B "$build_dir" $cmake_zta_arg
  else
    # Reused dir (--no-clean): refresh the cmake config in case CMake files
    # changed since last run, and to apply/keep -DAT_ZTA.
    cmake -S "$c_dir" -B "$build_dir" $cmake_zta_arg >/dev/null
  fi

  echo "Building + running C conformance harness ..."
  (cd "$build_dir" && make conformance_c)
}

# ---------------------------------------------------------------------------
# Cross-language diff
# ---------------------------------------------------------------------------

# Human-readable age of a file, so a reused results JSON reports how old it is
# rather than just its name.
file_age() {
  local f=$1 now mtime secs
  now=$(date +%s)
  mtime=$(stat -c %Y "$f" 2>/dev/null || echo "$now")
  secs=$(( now - mtime ))
  if   (( secs < 60 ));    then echo "${secs}s"
  elif (( secs < 3600 ));  then echo "$(( secs / 60 ))m"
  elif (( secs < 86400 )); then echo "$(( secs / 3600 ))h"
  else                          echo "$(( secs / 86400 ))d"
  fi
}

run_diff() {
  local py_result
  py_result=$(ls -1t "$py_dir"/conformance/results/python-*.json 2>/dev/null | head -n1 || true)
  if [[ -z "$py_result" ]]; then
    echo "diff: no python results JSON found under $py_dir/conformance/results/" >&2
    echo "diff: skipping (run without --c-only first to produce one)." >&2
    return 0
  fi

  # Staleness guard. `ls -1t | head -n1` picks the newest file by mtime, which is
  # NOT necessarily one this run produced -- that directory accumulates every
  # historical result (months of them). When the Python harness dies BEFORE
  # writing its JSON, an unguarded diff compares C against a previous run's file
  # and prints "0 asymmetric", which reads as cross-language agreement from a
  # Python run that never happened.
  #
  # Measured 2026-08-06: a pytest collection error (missing `jcs` and `dateutil`)
  # produced exactly that -- "0 asymmetric, only-python=0, only-c=0" against a
  # file 44 minutes old. The summary NOTE below does not cover this case: it warns
  # that agreement is not the same as passing, not that one side may be a fossil.
  if [[ -n "$py_run_marker" ]]; then
    # The Python harness ran this invocation, so it owes us a file newer than the
    # marker. Anything older means it wrote nothing and we must not pretend.
    if [[ ! "$py_result" -nt "$py_run_marker" ]]; then
      echo "diff: REFUSING to diff. The python harness ran this invocation but"   >&2
      echo "      produced no results JSON, so the newest one predates this run:" >&2
      echo "      $py_result ($(file_age "$py_result") old)"                      >&2
      echo "      Diffing against it would report agreement from a python run"    >&2
      echo "      that did not happen. Fix the harness (see its output above),"   >&2
      echo "      or use --c to diff deliberately against previous results."      >&2
      diff_refused=1
      return 1
    fi
  else
    # --c: reusing an earlier run's python results is the documented intent here,
    # so allow it -- but name the file and its age so it cannot pass for fresh.
    echo "diff: --c given, so the python side is a PREVIOUS run's results:" >&2
    echo "      $py_result ($(file_age "$py_result") old)"                  >&2
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
# Set by run_diff when it declines to compare because the python results were not
# produced by this run. Distinguished from a real asymmetry in the summary.
diff_refused=0

if (( ! c_only )); then
  # Stamp BEFORE the harness starts: run_diff requires the results JSON it
  # consumes to be newer than this, which is what proves the file came from this
  # run rather than from the pile of historical ones.
  py_run_marker=$(mktemp -t conformance-pyrun.XXXXXX)
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
  if (( diff_refused )); then
    echo "  asymmetry diff : NOT RUN -- refused, python results were not from this run"
    echo "                   (so symmetry is UNKNOWN, not confirmed)"
  else
    echo "  asymmetry diff : rc=$diff_rc   (0 = 0 asymmetric pass/fail)"
  fi
fi
if (( py_rc != 0 || c_rc != 0 )) && (( ! diff_refused )); then
  echo "  NOTE: a harness had failing cases; 'asymmetry diff rc=0' means the two" >&2
  echo "        sides AGREE per case, NOT that every case passed. Check the rc"  >&2
  echo "        lines above for actual pass/fail." >&2
fi

# Fail on any harness failure OR a true cross-language asymmetry.
if (( py_rc != 0 || c_rc != 0 || diff_rc != 0 )); then
  exit 1
fi
exit 0
