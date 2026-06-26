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
# Run the Python test suites from the repo root.

# Run everything relative to the repo root
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$here" || exit 1

usage() {
  cat <<'EOF'
Usage: test-packages.sh [OPTIONS] [pytest args...]

Build the C library, then run the Python test suites for each autonomous-trust
package. Extra arguments are forwarded to pytest (the flags consumed here are
stripped before forwarding).

Options:
  -q, --quick     Skip the two-node integration test.
  -v, --verbose   Verbose build and test output.
  -h, --help      Show this help message and exit.
EOF
}

status=0
quick=false
verbose=false
for arg in "$@"; do
    case "$arg" in
        --quick|-q) quick=true ;;
        --verbose|-v) verbose=true ;;
        --help|-h) usage; exit 0 ;;
    esac
done

# The suites below run via the bare `python -m pytest`, which expects the
# project's `autonomous_trust` conda env to be active so the interpreter
# carries the AT deps. Match the gating convention in scripts/build-py.sh;
# deferred past --help so usage still works without the env active.
CONDA_ENV_NAME="${CONDA_ENV_NAME:-autonomous_trust}"
if [[ "${CONDA_DEFAULT_ENV:-}" != "$CONDA_ENV_NAME" ]]; then
    echo "ERROR: conda environment '$CONDA_ENV_NAME' is not active." >&2
    echo "  Run: conda activate $CONDA_ENV_NAME" >&2
    exit 1
fi

echo "========== Building the C library =========="
if $verbose; then
  scripts/build.sh --c || exit 1
else
  scripts/build.sh --c >/dev/null || exit 1
fi

for pkg in autonomous-trust autonomous-trust-services autonomous-trust-inspector autonomous-trust-simulator autonomous-trust-behaviour; do
    pkg_dir="$here/src/$pkg"
    if [ -d "$pkg_dir/tests" ]; then
        echo "========== Testing $pkg =========="
        flags=
        if $verbose; then
          flags="-v"
        else
          flags="-q"
        fi
        cov_flags="--cov=autonomous_trust --cov-report=term-missing"
        if [ -f "$pkg_dir/.coveragerc" ]; then
          cov_flags="$cov_flags --cov-config=$pkg_dir/.coveragerc"
        fi
        quick_flags=
        if $quick; then
          quick_flags="--ignore=tests/b_integration/test_two_node.py"
        fi
        # Forward extra args to pytest, but strip the flags this script
        # consumes itself -- otherwise pytest sees e.g. --quick and errors with
        # "unrecognized arguments".
        pass_args=()
        for arg in "$@"; do
          case "$arg" in
            --quick|-q|--verbose|-v) ;;  # consumed above; don't forward
            *) pass_args+=("$arg") ;;
          esac
        done
        if [[ "$pkg" = "autonomous-trust" ]]; then
          # Test both backends
          echo "******** Testing native implementation ********"
          (cd "$pkg_dir" && AUTONOMOUS_TRUST_BACKEND=native python -m pytest tests/ $cov_flags --ignore=tests/local $quick_flags --continue-on-collection-errors $flags -s "${pass_args[@]}")
          echo "******** Testing python implementation ********"
          (cd "$pkg_dir" && AUTONOMOUS_TRUST_BACKEND=python python -m pytest tests/ $cov_flags --ignore=tests/local $quick_flags --continue-on-collection-errors $flags -s "${pass_args[@]}")
        else
          (cd "$pkg_dir" && python -m pytest tests/ $cov_flags --ignore=tests/local $quick_flags --continue-on-collection-errors $flags -s "${pass_args[@]}")
        fi
        rc=$?
        if [ $rc -eq 1 ]; then
            # Exit 1 = test failures; propagate as error
            status=1
        elif [ $rc -ne 0 ] && [ "$pkg" = "autonomous-trust" ]; then
            # For the core package, any non-zero exit is an error
            status=$rc
        fi
    fi
done

exit $status
