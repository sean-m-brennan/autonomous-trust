#!/usr/bin/env bash
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
# Run Phase 2 Appalachian scenarios and collect baseline metrics.
#
# Usage:
#   bash run-scenarios.sh [--terrain-csv PATH] [--freq-mhz FREQ]
#
# Prerequisites:
#   conda activate muudd_simulation
#
# Runs two scenarios:
#   1. 8-node hilltop-only (quick validation)
#   2. 20-node full mesh (hilltop + valley)
#
# Output:
#   metrics-hilltop-8.json   — 8-node results
#   metrics-full-20.json     — 20-node results
#   baseline-report.json     — consolidated baseline report
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SIM_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

TERRAIN_ARGS=""
DURATION=120

while [[ $# -gt 0 ]]; do
    case $1 in
        --terrain-csv)
            TERRAIN_ARGS="--terrain-csv $2"
            shift 2
            ;;
        --freq-mhz)
            TERRAIN_ARGS="$TERRAIN_ARGS --freq-mhz $2"
            shift 2
            ;;
        --duration)
            DURATION="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1" >&2
            echo "Usage: $0 [--terrain-csv PATH] [--freq-mhz FREQ] [--duration SEC]"
            exit 1
            ;;
    esac
done

echo "============================================"
echo "  MUUDD Phase 2: Appalachian Mesh Scenarios"
echo "============================================"
echo ""
echo "Duration per scenario: ${DURATION}s"
echo "Terrain args: ${TERRAIN_ARGS:-none}"
echo ""

# Scenario 1: 8-node hilltop only
echo "############################################"
echo "# Scenario 1: 8-node hilltop relay mesh    #"
echo "############################################"
echo ""
python -m autonomous_trust.simulator.scenarios.run_scenario \
    --hilltop-only \
    --duration "$DURATION" \
    --output metrics-hilltop-8.json \
    $TERRAIN_ARGS \
    || echo "WARNING: Scenario 1 exited with error"

echo ""
echo ""

# Scenario 2: 20-node full mesh
echo "############################################"
echo "# Scenario 2: 20-node full mesh            #"
echo "############################################"
echo ""
python -m autonomous_trust.simulator.scenarios.run_scenario \
    --duration "$DURATION" \
    --output metrics-full-20.json \
    $TERRAIN_ARGS \
    || echo "WARNING: Scenario 2 exited with error"

echo ""
echo ""

# Consolidate baseline report
echo "############################################"
echo "# Consolidating baseline report            #"
echo "############################################"
python -c "
import json, os, sys
from datetime import datetime

report = {
    'generated': datetime.now().isoformat(),
    'scenarios': {}
}

for name, path in [('hilltop_8', 'metrics-hilltop-8.json'),
                    ('full_20', 'metrics-full-20.json')]:
    if os.path.exists(path):
        with open(path) as f:
            report['scenarios'][name] = json.load(f)
        print('  Loaded: %s' % path)
    else:
        report['scenarios'][name] = {'error': 'no output produced'}
        print('  Missing: %s' % path)

with open('baseline-report.json', 'w') as f:
    json.dump(report, f, indent=2, default=str)

print('')
print('Baseline report written to: baseline-report.json')
print('')
print(json.dumps(report, indent=2, default=str))
"

echo ""
echo "Done. Output files:"
ls -la metrics-hilltop-8.json metrics-full-20.json baseline-report.json 2>/dev/null || true
