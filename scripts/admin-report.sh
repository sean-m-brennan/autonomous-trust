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
# Run the administrative-overhead M&S (SOW Task 2.4, "-25% net") and print the
# per-operator-action-class accounting (with vs without AT), the -25% net verdict,
# and a mission-tempo sensitivity sweep.
#
# MODELED / analytic (the softest Task 2 metric). AT-added burdens are counted
# explicitly; baseline rates are TPOC-pre-registration dependent (Task 2.2); the
# MissionValor interface is STUBBED (stands in for Sentar Task 1.5). Pure stdlib.
#
# Usage:
#   scripts/admin-report.sh                 # representative tempo (x1)
#   scripts/admin-report.sh --tempo 0.5     # low mission tempo
#   scripts/admin-report.sh --json out.json
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EVAL="$ROOT/src/autonomous-trust-evaluation"

PY="$(command -v python3 || command -v python || true)"
if [ -z "$PY" ]; then
    echo "error: no python found on PATH" >&2
    exit 1
fi

export PYTHONPATH="$EVAL${PYTHONPATH:+:$PYTHONPATH}"
exec "$PY" -m autonomous_trust.evaluation.mns.admin "$@"
