#!/bin/bash
# Run the Python test suites from the repo root

# Run everything relative to this script
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
cd "$here" || exit 1

status=0
quick=false
if [[ "$@" = *"--quick"* ]] || [[ "$@" = *"-q"* ]]; then
  quick=true
fi

echo "========== Building the C library =========="
if [[ "$@" = *"--verbose"* ]] || [[ "$@" = *"-v"* ]]; then
  ./build.sh --c || exit 1
else
  ./build.sh --c >/dev/null || exit 1
fi

for pkg in autonomous-trust autonomous-trust-services autonomous-trust-inspector autonomous-trust-simulator; do
    pkg_dir="$here/src/$pkg"
    if [ -d "$pkg_dir/tests" ]; then
        echo "========== Testing $pkg =========="
        flags=
        if [[ "$@" = *"--verbose"* ]] || [[ "$@" = *"-v"* ]]; then
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
        # Strip -q/--quick from passthrough args
        pass_args=()
        for arg in "$@"; do
          if [[ "$arg" != "-q" ]] && [[ "$arg" != "--quick" ]]; then
            pass_args+=("$arg")
          fi
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
