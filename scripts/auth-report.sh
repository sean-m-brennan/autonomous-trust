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
# Run the authentication-time M&S (SOW Task 2.4, "Auth <=5s") and print the three
# reported quantities: (1) steady-state re-authentication vs cohort (gated <=5s),
# (2) one-time enrollment duration (characterized, not gated), (3) degraded-edge
# first-contact admission (gated <=5s) vs a strict ZTA that blocks on the
# unreachable revocation source.
#
# MODELED (seeded). Per SOW the AT path is to be MEASURED on subscale HW (Task 4)
# and base-2 (hardware) attestation is modeled (M12). Pure stdlib; deterministic.
#
# Usage:
#   scripts/auth-report.sh                 # report (default seed 1234)
#   scripts/auth-report.sh --seed 7
#   scripts/auth-report.sh --json out.json
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EVAL="$ROOT/src/autonomous-trust-evaluation"

PY="$(command -v python3 || command -v python || true)"
if [ -z "$PY" ]; then
    echo "error: no python found on PATH" >&2
    exit 1
fi

export PYTHONPATH="$EVAL${PYTHONPATH:+:$PYTHONPATH}"
exec "$PY" -m autonomous_trust.evaluation.mns.auth "$@"
