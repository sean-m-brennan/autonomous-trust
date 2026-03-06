#!/bin/bash
# Run the Python test suites from the repo root

# Run everything relative to this script
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
cd "$here" || exit 1

status=0

echo "========== Building the C library =========="
if [[ "$@" = *"--verbose"* ]]; then
  ./build.sh --c
else
  ./build.sh --c >/dev/null
fi

for pkg in autonomous-trust autonomous-trust-services autonomous-trust-inspector autonomous-trust-simulator; do
    pkg_dir="$here/src/$pkg"
    if [ -d "$pkg_dir/tests" ]; then
        echo "========== Testing $pkg =========="
        flags=
        if [[ "$@" = *"--verbose"* ]]; then
          flags="-v"
        else
          flags="-q"
        fi
        cov_flags="--cov=autonomous_trust --cov-report=term-missing"
        if [ -f "$pkg_dir/.coveragerc" ]; then
          cov_flags="$cov_flags --cov-config=$pkg_dir/.coveragerc"
        fi
        (cd "$pkg_dir" && python -m pytest tests/ $cov_flags --ignore=tests/local --continue-on-collection-errors $flags -s "$@")
        if [[ "$pkg" = "autonomous-trust" ]]; then
          # Change backend
          (cd "$pkg_dir" && AUTONOMOUS_TRUST_BACKEND=python python -m pytest tests/ $cov_flags --ignore=tests/local --continue-on-collection-errors $flags -s "$@")
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
