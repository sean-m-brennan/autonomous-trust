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
# Run the access-decision latency M&S (SOW Task 2.4, "Latency -50%") and print
# the AT-local vs ZTA-PDP comparison, the -50% target verdict, and a robustness
# sweep over modeled link profiles (benign-LAN -> contested-tactical -> DDIL).
#
# All figures are MODELED (seeded Monte Carlo). The AT path is the one to be
# MEASURED on subscale hardware (Task 4); the ZTA baseline is modeled/anchored to
# published DoD-PKI/OCSP/CRL figures (Task 2.2).
#
# Usage:
#   scripts/latency-report.sh                 # report (default seed 1234, cohort 25)
#   scripts/latency-report.sh --seed 7
#   scripts/latency-report.sh --cohort 95     # heavier PDP contention
#   scripts/latency-report.sh --json out.json # also write the full JSON report
#
# Pure stdlib (no deps); deterministic under a fixed seed.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EVAL="$ROOT/src/autonomous-trust-evaluation"

PY="$(command -v python3 || command -v python || true)"
if [ -z "$PY" ]; then
    echo "error: no python found on PATH" >&2
    exit 1
fi

export PYTHONPATH="$EVAL${PYTHONPATH:+:$PYTHONPATH}"
exec "$PY" -m autonomous_trust.evaluation.mns "$@"
