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
# Run the unauthorized-access reduction M&S (SOW Task 2.4, "-90%") and print the
# with-vs-without-AT comparison over the ATT&CK-mapped attempt taxonomy, the -90%
# target verdict, and the reduction projected once the tracked gaps close.
#
# MODELED (seeded). Behavioural block-rates anchored to the red-team's MEASURED
# detection; the rest are modeled gates. The attempt mix is TPOC-pre-registration
# dependent (Task 2.2). Pure stdlib (no deps); deterministic under a fixed seed.
#
# Usage:
#   scripts/unauthorized-report.sh                 # report (default seed 1234)
#   scripts/unauthorized-report.sh --seed 7
#   scripts/unauthorized-report.sh --json out.json
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EVAL="$ROOT/src/autonomous-trust-evaluation"

PY="$(command -v python3 || command -v python || true)"
if [ -z "$PY" ]; then
    echo "error: no python found on PATH" >&2
    exit 1
fi

export PYTHONPATH="$EVAL${PYTHONPATH:+:$PYTHONPATH}"
exec "$PY" -m autonomous_trust.evaluation.mns.unauthorized "$@"
