#!/bin/bash
# Run the Python test suites from the repo root

# Run everything relative to this script
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

status=0

# Build C library
(cd src/c/build && cmake .. && make)

for pkg in autonomous-trust autonomous-trust-services autonomous-trust-inspector autonomous-trust-simulator; do
    pkg_dir="$here/src/$pkg"
    if [ -d "$pkg_dir/tests" ]; then
        echo "========== Testing $pkg =========="
        (cd "$pkg_dir" && python -m pytest tests/ --ignore=tests/local --continue-on-collection-errors -v -s "$@")
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
