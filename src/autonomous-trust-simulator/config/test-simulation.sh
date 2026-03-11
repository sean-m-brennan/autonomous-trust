#!/usr/bin/env bash
# Orchestrated launch for Appalachian scenario simulation.
#
# Usage:
#   bash test-simulation.sh [--hilltop-only] [--terrain-csv PATH]
#
# Prerequisites:
#   - conda activate muudd_simulation
#   - Docker daemon running
#   - AT Docker image built (docker build -t autonomous-trust ...)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SIM_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
AT_ROOT="$(cd "$SIM_DIR/../.." && pwd)"
WORK_DIR=$(mktemp -d)
trap 'echo "Cleaning up..."; docker compose -f "$WORK_DIR/docker-compose.yaml" down 2>/dev/null || true; rm -rf "$WORK_DIR"' EXIT

# Source local registry helpers (pull-or-build fallback)
source "$AT_ROOT/local-registry.sh" 2>/dev/null || true

HILLTOP_ONLY="False"
TERRAIN_CSV=""
TIMEOUT=180

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
        --timeout)
            TIMEOUT="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
    esac
done

echo "=== Appalachian Scenario Simulation ==="
echo "Work dir:     $WORK_DIR"
echo "Hilltop only: $HILLTOP_ONLY"
echo "Terrain CSV:  ${TERRAIN_CSV:-none}"
echo "Timeout:      ${TIMEOUT}s"
echo ""

# Step 1: Generate docker-compose
echo "Generating docker-compose configuration ..."
TERRAIN_ARG="None"
if [[ -n "$TERRAIN_CSV" ]]; then
    TERRAIN_ARG="'$TERRAIN_CSV'"
fi

python -c "
import sys
sys.path.insert(0, '$SIM_DIR')
from autonomous_trust.simulator.scenarios.appalachian_compose import generate_appalachian_compose
content = generate_appalachian_compose(
    hilltop_only=$HILLTOP_ONLY,
    terrain_config=$TERRAIN_ARG,
)
with open('$WORK_DIR/docker-compose.yaml', 'w') as f:
    f.write(content)
print('  Generated: $WORK_DIR/docker-compose.yaml')
"

# Step 2: Create Appalachian sim config
echo "Creating simulation config ..."
METRICS_FILE="$WORK_DIR/metrics.json"
python -c "
import sys
sys.path.insert(0, '$SIM_DIR')
from autonomous_trust.simulator.scenarios.appalachian import create_appalachian_config
cfg = create_appalachian_config(
    output_file='$WORK_DIR/appalachian.cfg',
    hilltop_only=$HILLTOP_ONLY,
)
print('  Config: ' + cfg)
"

# Step 3: Ensure AT Docker images are available (pull or build)
echo ""
echo "Ensuring Docker images are available ..."
require_image "autonomous-trust-devel" devel 2>/dev/null || true

# Step 4: Launch containers
echo ""
echo "Starting Docker containers ..."
docker compose -f "$WORK_DIR/docker-compose.yaml" up -d

# Step 5: Wait for completion or timeout
echo "Waiting for simulation (timeout: ${TIMEOUT}s) ..."
ELAPSED=0
while [[ $ELAPSED -lt $TIMEOUT ]]; do
    if [[ -f "$METRICS_FILE" ]]; then
        echo "Metrics file detected."
        break
    fi
    sleep 5
    ELAPSED=$((ELAPSED + 5))
    echo "  ${ELAPSED}s ..."
done

# Step 6: Collect results
echo ""
echo "=== Results ==="
if [[ -f "$METRICS_FILE" ]]; then
    echo "Metrics:"
    python -m json.tool "$METRICS_FILE"
else
    echo "WARNING: No metrics file produced within timeout."
    echo "Container logs:"
    docker compose -f "$WORK_DIR/docker-compose.yaml" logs --tail=20
fi

echo ""
echo "Stopping containers ..."
docker compose -f "$WORK_DIR/docker-compose.yaml" down
echo "Done."
