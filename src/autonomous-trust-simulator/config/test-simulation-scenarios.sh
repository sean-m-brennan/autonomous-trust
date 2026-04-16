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
# Orchestrated launch for scenario simulations (Appalachian or Asteroid Belt).
#
# Launches AT nodes in Docker containers with the first node running an
# instrumented entry point that collects protocol metrics via tee-queues.
#
# Usage:
#   bash test-simulation-scenarios.sh [--hilltop-only] [--quick] [--terrain-csv PATH] [--python] [--output PATH]
#   bash test-simulation-scenarios.sh --space [--python] [--output PATH] [--timeout SEC]
#
# Prerequisites:
#   - conda activate muudd_simulation
#   - Docker daemon running
#   - AT Docker image built (docker build -t autonomous-trust ...)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SIM_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
AT_ROOT="$(cd "$SIM_DIR/../.." && pwd)"
AT_SRC="$AT_ROOT/src"

# All four AT namespace packages must be importable
COVENANT_SRC="$(cd "$AT_ROOT/../kith-covenant/src/python" 2>/dev/null && pwd || echo "")"
export PYTHONPATH="${AT_SRC}/autonomous-trust:${AT_SRC}/autonomous-trust-services:${AT_SRC}/autonomous-trust-inspector:${AT_SRC}/autonomous-trust-simulator${COVENANT_SRC:+:$COVENANT_SRC}${PYTHONPATH:+:$PYTHONPATH}"
WORK_DIR=$(mktemp -d "${AT_ROOT}/.tmp-sim.XXXXXX")

cleanup() {
    echo "Cleaning up..."
    docker compose -f "$WORK_DIR/docker-compose.yaml" down --remove-orphans 2>/dev/null || true
    docker compose -f "$WORK_DIR/docker-compose.yaml" rm -f 2>/dev/null || true
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

# Source local registry helpers (pull-or-build fallback)
source "$AT_ROOT/local-registry.sh" 2>/dev/null || true

HILLTOP_ONLY="False"
TERRAIN_CSV=""
TIMEOUT=""
DURATION=""
BACKEND="native"
OUTPUT=""
CALDERA=""
CALDERA_ATTACKS=""
CALDERA_IMAGE="ghcr.io/mitre/caldera:5.2.0"
COVENANT_POLICY=""
COVENANT_OUTPUT=""
SPACE_MODE=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --hilltop-only)
            HILLTOP_ONLY="True"
            shift
            ;;
        --terrain-csv)
            TERRAIN_CSV="$2"
            shift 2
            ;;
        --quick)
            HILLTOP_ONLY="True"  # Full sim must run longer
            DURATION="180"
            shift
            ;;
        --timeout)
            TIMEOUT="$2"
            shift 2
            ;;
        --python)
            BACKEND="python"
            shift
            ;;
        --output)
            OUTPUT="$2"
            shift 2
            ;;
        --caldera)
            CALDERA="true"
            shift
            ;;
        --caldera-attacks)
            CALDERA_ATTACKS="$2"
            shift 2
            ;;
        --covenant-policy)
            COVENANT_POLICY="$2"
            shift 2
            ;;
        --covenant-output)
            COVENANT_OUTPUT="$2"
            shift 2
            ;;
        --space)
            SPACE_MODE="true"
            shift
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
    esac
done

# Default duration: 60 min for Appalachian, 12 hours for space
# (AT operations take ~2-3 hours per round trip at 30-min RTT).
# Timeout defaults to duration + 30s grace (Appalachian) or + 10min (space).
if [[ -z "$DURATION" ]]; then
    if [[ -n "$SPACE_MODE" ]]; then
        DURATION="43200"  # 12 hours
    else
        DURATION="3600"
    fi
fi
if [[ -z "$TIMEOUT" ]]; then
    if [[ -n "$SPACE_MODE" ]]; then
        TIMEOUT=$((DURATION + 600))
    else
        TIMEOUT=$((DURATION + 30))
    fi
fi

METRICS_DIR="$WORK_DIR/metrics"
mkdir -p "$METRICS_DIR"
METRICS_FILE="$METRICS_DIR/metrics.json"

if [[ -n "$SPACE_MODE" ]]; then
    SCENARIO_NAME="Asteroid Belt"
else
    SCENARIO_NAME="Appalachian"
fi

echo "=== ${SCENARIO_NAME} Scenario Simulation ==="
echo "Work dir:     $WORK_DIR"
if [[ -z "$SPACE_MODE" ]]; then
    echo "Hilltop only: $HILLTOP_ONLY"
    echo "Terrain CSV:  ${TERRAIN_CSV:-none}"
fi
echo "Backend:      $BACKEND"
echo "Output:       ${OUTPUT:-stdout only}"
echo "Duration:     ${DURATION}s"
echo "Timeout:      ${TIMEOUT}s"
if [[ -z "$SPACE_MODE" ]]; then
    echo "CALDERA:      ${CALDERA:-disabled}"
    echo "Attacks:      ${CALDERA_ATTACKS:-none}"
    echo "Covenant:     ${COVENANT_POLICY:-disabled}"
else
    echo "Space mode:   enabled (light-delay injection, FSPL link budget)"
fi
echo ""

# Step 1: Generate docker-compose
echo "Generating docker-compose configuration ..."
if [[ -n "$SPACE_MODE" ]]; then
    python -c "
import sys
sys.path.insert(0, '$SIM_DIR')
from examples.asteroid_belt.compose import generate_asteroid_belt_compose
content = generate_asteroid_belt_compose(
    backend='$BACKEND',
    metrics_dir='$METRICS_DIR',
)
with open('$WORK_DIR/docker-compose.yaml', 'w') as f:
    f.write(content)
print('  Generated: $WORK_DIR/docker-compose.yaml')
"
else
    TERRAIN_ARG="None"
    if [[ -n "$TERRAIN_CSV" ]]; then
        TERRAIN_ARG="'$TERRAIN_CSV'"
    fi

    python -c "
import sys
sys.path.insert(0, '$SIM_DIR')
from examples.appalachia.compose import generate_appalachian_compose
content = generate_appalachian_compose(
    hilltop_only=$HILLTOP_ONLY,
    terrain_config=$TERRAIN_ARG,
    backend='$BACKEND',
    metrics_dir='$METRICS_DIR',
)
with open('$WORK_DIR/docker-compose.yaml', 'w') as f:
    f.write(content)
print('  Generated: $WORK_DIR/docker-compose.yaml')
"
fi

# Step 1b: Patch compose with CALDERA server + sandcat (if --caldera)
if [[ -n "$CALDERA" ]]; then
    echo "Patching compose with CALDERA server + sandcat ..."
    python -c "
import sys, json, os
sys.path.insert(0, '$SIM_DIR')
from autonomous_trust.evaluation.redteam.caldera_compose import patch_caldera
with open('$WORK_DIR/docker-compose.yaml') as f:
    base = f.read()
attacks = '$CALDERA_ATTACKS'.split(',') if '$CALDERA_ATTACKS' else []
config = json.loads(os.environ.get('REDTEAM_ATTACK_CONFIG', '{}'))
patched = patch_caldera(base, attacks, config, work_dir='$WORK_DIR')
with open('$WORK_DIR/docker-compose.yaml', 'w') as f:
    f.write(patched)
print('  Patched with CALDERA server + sandcat')
"
fi

# Step 1c: Configure Covenant policy (if --covenant-policy)
if [[ -n "$COVENANT_POLICY" ]]; then
    echo "Configuring Covenant policy ..."
    # Resolve policy name to JSON file: try config/policy/<name>.json first,
    # then treat as a literal file path.
    POLICY_DIR="$SCRIPT_DIR/policy"
    if [[ -f "$POLICY_DIR/${COVENANT_POLICY}.json" ]]; then
        COVENANT_POLICY_FILE="$POLICY_DIR/${COVENANT_POLICY}.json"
    elif [[ -f "$COVENANT_POLICY" ]]; then
        COVENANT_POLICY_FILE="$COVENANT_POLICY"
    else
        echo "ERROR: Policy '$COVENANT_POLICY' not found." >&2
        echo "  Looked for: $POLICY_DIR/${COVENANT_POLICY}.json" >&2
        echo "  Also tried as file path: $COVENANT_POLICY" >&2
        echo "  Available policies: $(ls "$POLICY_DIR"/*.json 2>/dev/null | xargs -I{} basename {} .json | tr '\n' ' ')" >&2
        exit 1
    fi
    cp "$COVENANT_POLICY_FILE" "$WORK_DIR/covenant-policy.json"
    COVENANT_OUTPUT="${COVENANT_OUTPUT:-$METRICS_DIR/covenant.json}"
    echo "  Policy: $COVENANT_POLICY (from $COVENANT_POLICY_FILE)"
    echo "  Observer output: $COVENANT_OUTPUT"
fi

# Step 2: Create sim config
echo "Creating simulation config ..."
if [[ -n "$SPACE_MODE" ]]; then
    python -c "
import sys
from datetime import timedelta
sys.path.insert(0, '$SIM_DIR')
from examples.asteroid_belt.scenario import create_asteroid_belt_config
cfg = create_asteroid_belt_config(
    output_file='$WORK_DIR/asteroid_belt.cfg',
    duration=timedelta(seconds=$DURATION),
)
print('  Config: ' + cfg)
"
else
    python -c "
import sys
from datetime import timedelta
sys.path.insert(0, '$SIM_DIR')
from examples.appalachia.scenario import create_appalachian_config
cfg = create_appalachian_config(
    output_file='$WORK_DIR/appalachian.cfg',
    hilltop_only=$HILLTOP_ONLY,
    duration=timedelta(seconds=$DURATION),
)
print('  Config: ' + cfg)
"
fi

# Step 3: Ensure AT Docker images are available (pull or build)
echo ""
echo "Ensuring Docker images are available ..."
require_image "autonomous-trust-devel" devel
require_image "autonomous-trust-full-devel" full-devel

# Step 3b: Pull CALDERA image if needed
if [[ -n "$CALDERA" ]]; then
    echo "Pulling CALDERA image ..."
    docker pull "$CALDERA_IMAGE" 2>/dev/null || echo "  (using cached image)"
fi

# Step 4: Launch containers
echo ""
echo "Starting Docker containers ..."
docker compose -f "$WORK_DIR/docker-compose.yaml" up -d

# Step 5: Let simulation run, then stop gracefully to trigger metrics write.
# NOTE: Do NOT use metrics file existence to detect completion —
# MetricsCollector writes periodic snapshots every 30s for crash resilience,
# which does not indicate the simulation has finished.
echo "Running simulation for ${TIMEOUT}s ..."
ELAPSED=0
while [[ $ELAPSED -lt $TIMEOUT ]]; do
    # Check if any container has exited (unexpected early termination).
    EXITED=$(docker compose -f "$WORK_DIR/docker-compose.yaml" ps --filter "status=exited" --format '{{.Name}}' 2>/dev/null | head -1)
    if [[ -n "$EXITED" ]]; then
        echo "Container $EXITED exited early — collecting results."
        break
    fi
    sleep 5
    ELAPSED=$((ELAPSED + 5))
    # Print progress every 30s to avoid log spam
    if (( ELAPSED % 30 == 0 )); then
        echo "  ${ELAPSED}s / ${TIMEOUT}s ..."
    fi
done

# Step 6: Gracefully stop containers so MetricsCollector writes its report
echo ""
echo "Stopping containers to collect metrics ..."
docker compose -f "$WORK_DIR/docker-compose.yaml" stop -t 60
# Brief wait for metrics file to be flushed to the bind-mounted volume
sleep 3

# Step 7: Collect results
echo ""
echo "=== Results ==="
if [[ -f "$METRICS_FILE" ]]; then
    echo "Metrics file: $METRICS_FILE"
    echo "Metrics:"
    python -m json.tool "$METRICS_FILE"

    # Check against targets (Phase 2 for Appalachian, Phase 5 for space)
    python -c "
import json, sys
space_mode = '$SPACE_MODE'
with open('$METRICS_FILE') as f:
    r = json.load(f)
print()
if space_mode:
    print('--- Phase 5 Space Target Assessment ---')
    print('(Targets account for multi-minute RTT)')
    conv = r.get('identity_convergence_s')
    if conv is not None:
        # Identity admission: 4 round trips at ~30 min RTT = ~2.6 hrs
        # Allow up to 4 hours for convergence
        s = 'PASS' if conv < 14400 else 'FAIL'
        print('Identity convergence: %.0fs / %.1fh (target <4h) [%s]' % (conv, conv/3600, s))
    else:
        print('Identity convergence: no data')
    rep = r.get('reputation_stability_stddev')
    if rep is not None:
        # Reputation may be less stable under intermittent connectivity
        s = 'PASS' if rep < 0.15 else 'FAIL'
        print('Reputation stability: sigma=%.4f (target <0.15) [%s]' % (rep, s))
    else:
        print('Reputation stability: no data')
    rtt = r.get('negotiation_rtt_mean_s')
    if rtt is not None:
        # Negotiation: 3 round trips at ~30 min = ~1.9 hrs
        print('Negotiation RTT: %.0fs / %.1fh (N=%d)' % (rtt, rtt/3600, r.get('negotiation_rtt_count', 0)))
    else:
        print('Negotiation RTT: no data')
    bw = r.get('bandwidth_overhead_fraction')
    if bw is not None:
        # Bandwidth is very constrained in space (100 Kbps - 10 Mbps)
        s = 'PASS' if bw < 0.25 else 'FAIL'
        print('Bandwidth overhead: %.1f%% (target <25%%) [%s]' % (bw * 100, s))
    else:
        print('Bandwidth overhead: no data')
else:
    print('--- Phase 2 Target Assessment ---')
    conv = r.get('identity_convergence_s')
    if conv is not None:
        s = 'PASS' if conv < 90 else 'FAIL'
        print('Identity convergence: %.1fs (target <90s) [%s]' % (conv, s))
    else:
        print('Identity convergence: no data')
    rep = r.get('reputation_stability_stddev')
    if rep is not None:
        s = 'PASS' if rep < 0.05 else 'FAIL'
        print('Reputation stability: sigma=%.4f (target <0.05) [%s]' % (rep, s))
    else:
        print('Reputation stability: no data')
    rtt = r.get('negotiation_rtt_mean_s')
    if rtt is not None:
        print('Negotiation RTT: %.2fs (N=%d)' % (rtt, r.get('negotiation_rtt_count', 0)))
    else:
        print('Negotiation RTT: no data')
    bw = r.get('bandwidth_overhead_fraction')
    if bw is not None:
        s = 'PASS' if bw < 0.15 else 'FAIL'
        print('Bandwidth overhead: %.1f%% (target <15%%) [%s]' % (bw * 100, s))
    else:
        print('Bandwidth overhead: no data')
"

    if [[ -n "$OUTPUT" ]]; then
        mkdir -p "$(dirname "$OUTPUT")"
        cp "$METRICS_FILE" "$OUTPUT"
        OUTPUT_FULL="$(cd "$(dirname "$OUTPUT")" && pwd)/$(basename "$OUTPUT")"
        echo ""
        echo "Saved to: $OUTPUT_FULL"
    fi
else
    echo "WARNING: No metrics file produced within timeout."
    echo "Container logs:"
    docker compose -f "$WORK_DIR/docker-compose.yaml" logs --tail=30
fi

echo ""
echo "Done."
