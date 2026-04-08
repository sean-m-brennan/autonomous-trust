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
# Run Frama-C WP verification on ACSL-annotated C sources.
# Invoked from the repo root (or auto-detects it from scripts/).

set -euo pipefail

####################
# Constants
####################

PROJ_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
C_SRC="$PROJ_ROOT/src/c/autonomous_trust"
STUBS_DIR="$PROJ_ROOT/src/c/frama-c/stubs"

VALID_MODULES=(
    structures
    identity
    network
    config
    processes
    algorithms
    negotiation
    reputation
    fleet
    zta
    utilities
)

####################
# Defaults
####################

module=""
single_file=""
timeout=30
prover="alt-ergo"
do_report=0

####################
# Usage
####################

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Run Frama-C WP (Weakest Precondition) verification on ACSL-annotated C sources
in the AutonomousTrust project.

Options:
  --module <name>     Verify only one module. Valid modules:
                        $(printf '%s, ' "${VALID_MODULES[@]}" | sed 's/, $//')
  --file <path>       Verify a single .c file (relative to repo root or absolute)
  --timeout <seconds> Per-goal SMT solver timeout (default: $timeout)
  --prover <name>     SMT solver backend (default: $prover)
                        Common choices: alt-ergo, z3, cvc4, cvc5
  --report            Write results to frama-c-report.csv in the repo root
  -h, --help          Show this help message and exit

Examples:
  # Verify everything
  $(basename "$0")

  # Verify only the structures module
  $(basename "$0") --module structures

  # Verify a single file with Z3 and a 60-second timeout
  $(basename "$0") --file src/c/autonomous_trust/structures/array.c \\
                   --prover z3 --timeout 60

  # Verify all modules and produce a CSV report
  $(basename "$0") --report
EOF
    exit "${1:-0}"
}

####################
# Argument parsing
####################

while [[ $# -gt 0 ]]; do
    case "$1" in
        --module)
            [[ $# -lt 2 ]] && { echo "ERROR: --module requires an argument"; usage 1; }
            module="$2"
            shift 2
            ;;
        --file)
            [[ $# -lt 2 ]] && { echo "ERROR: --file requires an argument"; usage 1; }
            single_file="$2"
            shift 2
            ;;
        --timeout)
            [[ $# -lt 2 ]] && { echo "ERROR: --timeout requires an argument"; usage 1; }
            timeout="$2"
            shift 2
            ;;
        --prover)
            [[ $# -lt 2 ]] && { echo "ERROR: --prover requires an argument"; usage 1; }
            prover="$2"
            shift 2
            ;;
        --report)
            do_report=1
            shift
            ;;
        -h|--help)
            usage 0
            ;;
        *)
            echo "ERROR: Unknown argument: $1"
            usage 1
            ;;
    esac
done

####################
# Validate module
####################

if [[ -n "$module" ]]; then
    valid=0
    for m in "${VALID_MODULES[@]}"; do
        if [[ "$m" == "$module" ]]; then
            valid=1
            break
        fi
    done
    if [[ $valid -eq 0 ]]; then
        echo "ERROR: Unknown module '$module'."
        echo "Valid modules: $(printf '%s, ' "${VALID_MODULES[@]}" | sed 's/, $//')"
        exit 1
    fi
fi

####################
# Locate frama-c
####################

FRAMAC=""

if command -v frama-c >/dev/null 2>&1; then
    FRAMAC="frama-c"
elif command -v opam >/dev/null 2>&1; then
    # Try to find frama-c via opam
    opam_bin=$(opam var bin 2>/dev/null || true)
    if [[ -n "$opam_bin" && -x "$opam_bin/frama-c" ]]; then
        FRAMAC="$opam_bin/frama-c"
    fi
fi

if [[ -z "$FRAMAC" ]]; then
    echo "ERROR: frama-c not found in PATH or via opam."
    echo ""
    echo "Install with:  opam install frama-c"
    echo "Or see:        https://frama-c.com/install.html"
    exit 1
fi

framac_version=$("$FRAMAC" -version 2>&1 | head -1)
echo "Frama-C: $framac_version"
echo "Prover:  $prover"
echo "Timeout: ${timeout}s per goal"
echo ""

####################
# Collect source files
####################

declare -a files=()

if [[ -n "$single_file" ]]; then
    # Resolve relative paths against the project root
    if [[ "$single_file" != /* ]]; then
        single_file="$PROJ_ROOT/$single_file"
    fi
    if [[ ! -f "$single_file" ]]; then
        echo "ERROR: File not found: $single_file"
        exit 1
    fi
    files+=("$single_file")
elif [[ -n "$module" ]]; then
    mod_dir="$C_SRC/$module"
    if [[ ! -d "$mod_dir" ]]; then
        echo "ERROR: Module directory not found: $mod_dir"
        exit 1
    fi
    while IFS= read -r -d '' f; do
        files+=("$f")
    done < <(find "$mod_dir" -name '*.c' -type f -print0 | sort -z)
else
    # All modules
    for m in "${VALID_MODULES[@]}"; do
        mod_dir="$C_SRC/$m"
        if [[ -d "$mod_dir" ]]; then
            while IFS= read -r -d '' f; do
                files+=("$f")
            done < <(find "$mod_dir" -name '*.c' -type f -print0 | sort -z)
        fi
    done
fi

if [[ ${#files[@]} -eq 0 ]]; then
    echo "ERROR: No .c files found to verify."
    exit 1
fi

echo "Files to verify: ${#files[@]}"
echo ""

####################
# Include paths
####################

INCLUDE_FLAGS=(
    -cpp-extra-args="-I $C_SRC -I $STUBS_DIR -I $PROJ_ROOT/src/c"
)

####################
# WP flags
####################

WP_FLAGS=(
    -wp
    -wp-prover "$prover"
    -wp-timeout "$timeout"
    -wp-smoke-tests
    -kernel-warn-key annot-error=active
    -kernel-warn-key annot:missing-spec=active
    -wp-print
)

####################
# Run verification
####################

# Accumulators for summary
declare -a result_files=()
declare -a result_proved=()
declare -a result_failed=()
declare -a result_timeout=()
declare -a result_total=()
declare -a result_status=()

total_proved=0
total_failed=0
total_timeout=0
total_goals=0
any_failure=0

for src in "${files[@]}"; do
    rel_path="${src#"$PROJ_ROOT"/}"
    echo "========== $rel_path =========="

    # Run frama-c and capture output
    set +e
    output=$("$FRAMAC" "${WP_FLAGS[@]}" "${INCLUDE_FLAGS[@]}" "$src" 2>&1)
    rc=$?
    set -e

    # Parse proved/failed/timeout counts from WP output.
    # Frama-C WP typically prints lines like:
    #   Proved goals:   42 / 50
    #   Qed:            30
    #   Alt-Ergo:       12
    #   Failed goals:    8 / 50
    #   Timeout:         3
    # We look for the summary line and various status indicators.

    proved=0
    failed=0
    timed_out=0
    file_goals=0

    # Try to extract from the "Proved goals: N / M" line
    proved_line=$(echo "$output" | grep -i 'Proved goals' | tail -1 || true)
    if [[ -n "$proved_line" ]]; then
        proved=$(echo "$proved_line" | grep -oP '\d+\s*/\s*\d+' | head -1 | cut -d'/' -f1 | tr -d ' ' || echo 0)
        file_goals=$(echo "$proved_line" | grep -oP '\d+\s*/\s*\d+' | head -1 | cut -d'/' -f2 | tr -d ' ' || echo 0)
    fi

    # Count timeout goals
    timeout_line=$(echo "$output" | grep -iP '^\s*Timeout' | tail -1 || true)
    if [[ -n "$timeout_line" ]]; then
        timed_out=$(echo "$timeout_line" | grep -oP '\d+' | tail -1 || echo 0)
    fi

    # If we got a total from the proved line, compute failed
    if [[ $file_goals -gt 0 ]]; then
        failed=$((file_goals - proved))
    else
        # Fallback: count individual goal statuses in the output
        proved=$(echo "$output" | grep -cP '\bValid\b' || true)
        failed=$(echo "$output" | grep -cP '\bUnknown\b|\bInvalid\b|\bFailed\b' || true)
        timed_out=$(echo "$output" | grep -cP '\bTimeout\b' || true)
        file_goals=$((proved + failed + timed_out))
    fi

    # Determine file status
    file_status="PASS"
    if [[ $rc -ne 0 ]]; then
        file_status="ERROR"
        any_failure=1
    elif [[ $failed -gt 0 || $timed_out -gt 0 ]]; then
        # Check if this file is in the stubs directory (stubs failures are non-fatal)
        if [[ "$src" == "$STUBS_DIR"* ]]; then
            file_status="STUB"
        else
            file_status="FAIL"
            any_failure=1
        fi
    fi

    # Print per-file result
    printf "  Goals: %d  Proved: %d  Failed: %d  Timeout: %d  [%s]\n" \
        "$file_goals" "$proved" "$failed" "$timed_out" "$file_status"

    if [[ $rc -ne 0 ]]; then
        echo "  Frama-C exited with code $rc"
        # Print last few lines of output for diagnostics
        echo "$output" | tail -10 | sed 's/^/  | /'
    fi

    echo ""

    # Accumulate
    result_files+=("$rel_path")
    result_proved+=("$proved")
    result_failed+=("$failed")
    result_timeout+=("$timed_out")
    result_total+=("$file_goals")
    result_status+=("$file_status")

    total_proved=$((total_proved + proved))
    total_failed=$((total_failed + failed))
    total_timeout=$((total_timeout + timed_out))
    total_goals=$((total_goals + file_goals))
done

####################
# Summary table
####################

echo "=========================================="
echo "  Frama-C WP Verification Summary"
echo "=========================================="
echo ""

# Header
printf "  %-50s %6s %7s %7s %8s  %s\n" "File" "Goals" "Proved" "Failed" "Timeout" "Status"
printf "  %-50s %6s %7s %7s %8s  %s\n" "----" "-----" "------" "------" "-------" "------"

for i in "${!result_files[@]}"; do
    printf "  %-50s %6d %7d %7d %8d  %s\n" \
        "${result_files[$i]}" \
        "${result_total[$i]}" \
        "${result_proved[$i]}" \
        "${result_failed[$i]}" \
        "${result_timeout[$i]}" \
        "${result_status[$i]}"
done

echo ""
printf "  %-50s %6d %7d %7d %8d\n" "TOTAL" "$total_goals" "$total_proved" "$total_failed" "$total_timeout"
echo ""

if [[ $total_goals -gt 0 ]]; then
    pct=$((total_proved * 100 / total_goals))
    echo "  Proof coverage: ${pct}% ($total_proved / $total_goals goals proved)"
else
    echo "  No proof obligations found."
fi

echo "=========================================="

####################
# CSV report
####################

if [[ $do_report -eq 1 ]]; then
    report_file="$PROJ_ROOT/frama-c-report.csv"
    {
        echo "file,goals,proved,failed,timeout,status"
        for i in "${!result_files[@]}"; do
            echo "\"${result_files[$i]}\",${result_total[$i]},${result_proved[$i]},${result_failed[$i]},${result_timeout[$i]},${result_status[$i]}"
        done
        echo "\"TOTAL\",$total_goals,$total_proved,$total_failed,$total_timeout,"
    } > "$report_file"
    echo ""
    echo "Report written to: $report_file"
fi

####################
# Exit status
####################

if [[ $any_failure -ne 0 ]]; then
    echo ""
    echo "RESULT: FAIL - Some proof obligations were not discharged."
    exit 1
else
    echo ""
    echo "RESULT: PASS - All proof obligations discharged."
    exit 0
fi
