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

status=0
quick=false
verbose=false
for arg in "$@"; do
    case "$arg" in
        --quick|-q) quick=true ;;
        --verbose|-v) verbose=true ;;
    esac
done

echo "========== Building the C library =========="
if $verbose; then
  scripts/build.sh --c || exit 1
else
  scripts/build.sh --c >/dev/null || exit 1
fi

for pkg in autonomous-trust autonomous-trust-services autonomous-trust-inspector autonomous-trust-simulator; do
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
