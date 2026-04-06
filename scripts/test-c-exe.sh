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
# Run the C test suites from the repo root.
# Mirrors test-packages.sh for the C library.

# Run everything relative to the repo root
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$here" || exit 1

status=0
c_dir="$here/src/c"
build_dir="$c_dir/build"

verbose=0
coverage=0
filter=""
for arg in "$@"; do
    case "$arg" in
        --verbose|-v) verbose=1 ;;
        --coverage|-c) coverage=1 ;;
        --filter=*)   filter="${arg#--filter=}" ;;
    esac
done

####################
# Build
####################

echo "========== Building C library and tests =========="

rm -rf "$build_dir"
mkdir -p "$build_dir"

cmake_flags=("-DCMAKE_BUILD_TYPE=Debug")
# Enable ZTA integration (requires OpenSSL) so ZTA unit tests are built
cmake_flags+=("-DAT_ZTA=ON")
# Use clang if available (avoids GCC 14/15 + binutils 2.45 corrupt ELF bugs)
if command -v clang >/dev/null 2>&1 && command -v clang++ >/dev/null 2>&1; then
    cmake_flags+=("-DCMAKE_C_COMPILER=clang" "-DCMAKE_CXX_COMPILER=clang++")
fi
# Use LLVM ar/ranlib/linker if available (try unversioned, then versioned)
llvm_ar=""
for tool in llvm-ar llvm-ar-20 llvm-ar-19 llvm-ar-18; do
    if command -v "$tool" >/dev/null 2>&1; then
        llvm_ar="$tool"
        break
    fi
done
if [ -n "$llvm_ar" ]; then
    ver_suffix="${llvm_ar#llvm-ar}"  # e.g. "-20" or ""
    cmake_flags+=("-DCMAKE_AR=$(which "$llvm_ar")" "-DCMAKE_RANLIB=$(which "llvm-ranlib${ver_suffix}")")
    # Only use lld if actually installed
    lld_tool=""
    for candidate in "lld${ver_suffix}" lld; do
        if command -v "$candidate" >/dev/null 2>&1; then
            lld_tool="$candidate"
            break
        fi
    done
    if [ -n "$lld_tool" ]; then
        linker_flags="-fuse-ld=$lld_tool"
        if [ $coverage -eq 1 ]; then
            linker_flags="--coverage $linker_flags"
        fi
        cmake_flags+=("-DCMAKE_EXE_LINKER_FLAGS=$linker_flags" "-DCMAKE_SHARED_LINKER_FLAGS=$linker_flags")
    elif [ $coverage -eq 1 ]; then
        cmake_flags+=("-DCMAKE_EXE_LINKER_FLAGS=--coverage" "-DCMAKE_SHARED_LINKER_FLAGS=--coverage")
    fi
fi
# Add coverage instrumentation flags
if [ $coverage -eq 1 ]; then
    cmake_flags+=("-DCMAKE_C_FLAGS=-g -O0 --coverage" "-DCMAKE_CXX_FLAGS=-g -O0 --coverage")
fi
if [ $verbose -eq 1 ]; then
    (cd "$build_dir" && cmake .. "${cmake_flags[@]}")
else
    (cd "$build_dir" && cmake .. "${cmake_flags[@]}" 2>&1) | tail -5
fi

(cd "$build_dir" && make -j"$(nproc)" 2>&1)
rc=$?
if [ $rc -ne 0 ]; then
    echo "FAIL: C build failed (exit $rc)"
    exit $rc
fi

####################
# Run tests
####################

echo ""
echo "========== Running C tests =========="

# Collect test names from ctest
cd "$build_dir" || exit 1
tests=$(ctest --show-only=json-v1 2>/dev/null | python3 -c "
import sys, json
data = json.load(sys.stdin)
for t in data.get('tests', []):
    print(t['name'])
" 2>/dev/null)

if [ -z "$tests" ]; then
    # Fallback: run all via ctest
    tests=$(ctest -N 2>/dev/null | grep 'Test #' | sed 's/.*: //')
fi

passed=0
failed=0
skipped=0
failures=""

for t in $tests; do
    # Apply filter if specified
    if [ -n "$filter" ] && [[ "$t" != *"$filter"* ]]; then
        continue
    fi

    if [ $verbose -eq 1 ]; then
        echo ""
        echo "---------- $t ----------"
        ctest -R "^${t}$" --output-on-failure --no-label-summary 2>&1
    else
        output=$(ctest -R "^${t}$" --output-on-failure --no-label-summary 2>&1)
    fi
    rc=$?

    if [ $rc -eq 0 ]; then
        passed=$((passed + 1))
        if [ $verbose -eq 0 ]; then
            echo "  PASS  $t"
        fi
    else
        failed=$((failed + 1))
        failures="$failures  FAIL  $t\n"
        status=1
        if [ $verbose -eq 0 ]; then
            echo "  FAIL  $t"
            echo "$output" | grep -E "FAIL|assert|Error" | head -10
        fi
    fi
done

####################
# Summary
####################

total=$((passed + failed + skipped))
echo ""
echo "========== C Test Summary =========="
echo "  Total:   $total"
echo "  Passed:  $passed"
echo "  Failed:  $failed"
if [ $failed -gt 0 ]; then
    echo ""
    echo "Failures:"
    echo -e "$failures"
fi
echo "===================================="

####################
# Coverage
####################

if [ $coverage -eq 1 ]; then
    echo ""
    echo "========== Code Coverage =========="

    cov_dir="$build_dir/coverage"
    mkdir -p "$cov_dir"

    # Match llvm-cov version to the clang that compiled the code
    llvm_cov="llvm-cov"
    clang_ver=$(clang --version 2>/dev/null | head -1 | grep -o '[0-9]*\.' | head -1 | tr -d '.')
    if [ -n "$clang_ver" ] && command -v "llvm-cov-${clang_ver}" >/dev/null 2>&1; then
        llvm_cov="llvm-cov-${clang_ver}"
    fi

    # Create llvm-gcov wrapper (lcov requires gcov-compatible interface)
    gcov_tool="$cov_dir/llvm-gcov.sh"
    cat > "$gcov_tool" <<GCOV
#!/bin/bash
exec $llvm_cov gcov "\$@"
GCOV
    chmod +x "$gcov_tool"

    # Capture raw coverage data
    echo "  Capturing coverage data..."
    lcov_flags=()
    # lcov 2.x supports --ignore-errors; 1.x does not
    lcov_ver=$(lcov --version 2>&1 | grep -o '[0-9]*' | head -1)
    if [ "$lcov_ver" -ge 2 ] 2>/dev/null; then
        lcov_flags+=(--ignore-errors unsupported,unsupported)
        lcov_flags+=(--ignore-errors inconsistent,inconsistent)
        lcov_flags+=(--ignore-errors empty,empty)
    fi

    lcov --capture --directory "$build_dir" \
         --output-file "$cov_dir/raw.info" \
         --gcov-tool "$gcov_tool" \
         "${lcov_flags[@]}" 2>&1 | tail -3

    if [ ! -s "$cov_dir/raw.info" ]; then
        echo "  WARNING: lcov capture produced no data."
        echo "  Checking for .gcda files..."
        gcda_count=$(find "$build_dir" -name "*.gcda" 2>/dev/null | wc -l)
        gcno_count=$(find "$build_dir" -name "*.gcno" 2>/dev/null | wc -l)
        echo "  Found $gcno_count .gcno files, $gcda_count .gcda files"
        if [ "$gcda_count" -eq 0 ]; then
            echo "  No .gcda files — coverage data was not generated at runtime."
            echo "  Trying to generate via llvm-profdata + llvm-cov export..."
            # Clang may use profraw instead of gcda
            profraw_count=$(find "$build_dir" -name "*.profraw" 2>/dev/null | wc -l)
            echo "  Found $profraw_count .profraw files"
        fi
        echo "  gcov-tool: $gcov_tool"
        echo "  llvm-cov:  $($llvm_cov --version 2>&1 | head -1)"
        echo "  clang:     $(clang --version 2>&1 | head -1)"
        echo "  lcov:      $(lcov --version 2>&1)"
        echo "===================================="
        exit $status
    fi

    # Filter out protobuf generated code, test files, and system headers
    lcov --remove "$cov_dir/raw.info" \
         '*/protobuf/*' '*/test/*' '/usr/*' \
         --output-file "$cov_dir/filtered.info" \
         --gcov-tool "$gcov_tool" \
         "${lcov_flags[@]}" 2>&1 | tail -3

    # Print per-file summary
    echo ""
    lcov --list "$cov_dir/filtered.info" 2>/dev/null

    # Print overall summary
    echo ""
    summary=$(lcov --summary "$cov_dir/filtered.info" 2>&1)
    lines_pct=$(echo "$summary" | grep 'lines' | sed 's/.*: //' | grep -o '[0-9.]*%')
    funcs_pct=$(echo "$summary" | grep 'functions' | sed 's/.*: //' | grep -o '[0-9.]*%')
    echo "  Lines:     $lines_pct"
    echo "  Functions: $funcs_pct"

    # Generate HTML report if genhtml is available
    if command -v genhtml >/dev/null 2>&1; then
        html_dir="$cov_dir/html"
        genhtml "$cov_dir/filtered.info" \
                --output-directory "$html_dir" \
                --quiet 2>/dev/null
        echo ""
        echo "  HTML report: $html_dir/index.html"
    fi

    echo "===================================="
fi

exit $status
