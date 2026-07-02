#!/bin/bash
# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
#  Licensed under the Apache License, Version 2.0
# ******************
#
# run-demo.sh — Build and run the multi-agency disaster response demo.
#
# Usage:
#   ./run-demo.sh [--skip-build] [--playback FILE] [--speed N]
#                  [--compromise-mode gradual|abrupt]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
EXAMPLE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$EXAMPLE_DIR/../.." && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yml"

# Image names (must be built in order)
BASE_IMAGE="autonomous-trust-devel"
FULL_IMAGE="autonomous-trust-full-devel"
DEMO_IMAGE="at-multi-agency-demo"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log() { echo -e "${CYAN}[demo]${NC} $*"; }
warn() { echo -e "${YELLOW}[demo]${NC} $*"; }
err() { echo -e "${RED}[demo]${NC} $*" >&2; }
event() { echo -e "${GREEN}[T+${1}]${NC} $2"; }

# Parse args
do_build=1
playback_file=""
speed=1
compromise_mode="abrupt"

for arg in "$@"; do
    case "$arg" in
        --skip-build)      do_build=0 ;;
        --playback=*)      playback_file="${arg#--playback=}" ;;
        --speed=*)         speed="${arg#--speed=}" ;;
        --compromise-mode=*) compromise_mode="${arg#--compromise-mode=}" ;;
    esac
done

# Build the image chain
if [ "$do_build" -eq 1 ]; then
    # Check for base image
    if ! docker image inspect "$BASE_IMAGE" >/dev/null 2>&1; then
        log "Building base image: $BASE_IMAGE ..."
        docker build --network host -t "$BASE_IMAGE" \
            -f "$REPO_ROOT/src/autonomous-trust/Dockerfile-devel" "$REPO_ROOT"
    fi

    if ! docker image inspect "$FULL_IMAGE" >/dev/null 2>&1; then
        log "Building full stack image: $FULL_IMAGE ..."
        docker build --network host -t "$FULL_IMAGE" \
            -f "$REPO_ROOT/src/Dockerfile-devel" "$REPO_ROOT"
    fi

    log "Building multi-agency demo image: $DEMO_IMAGE ..."
    docker build --network host -t "$DEMO_IMAGE" \
        -f "$SCRIPT_DIR/Dockerfile" "$REPO_ROOT"
elif ! docker image inspect "$DEMO_IMAGE" >/dev/null 2>&1; then
    err "Image '$DEMO_IMAGE' not found and --skip-build was set."
    err "Build the image chain first:"
    err "  docker build -t $BASE_IMAGE -f src/autonomous-trust/Dockerfile-devel ."
    err "  docker build -t $FULL_IMAGE -f src/Dockerfile-devel ."
    err "  docker build -t $DEMO_IMAGE -f examples/multi_agency/deploy/Dockerfile ."
    exit 1
fi

# Generate per-peer configs
log "Generating peer configurations..."
cd "$REPO_ROOT"
python3 -c "
import sys; sys.path.insert(0, '.')
from autonomous_trust.evaluation.deployment import generate_peer_configs
from examples.multi_agency.scenario import DisasterResponseScenario
scenario = DisasterResponseScenario()
generate_peer_configs(scenario, 'examples/multi_agency')
print(f'  Generated configs for {len(scenario.peers)} peers')
" || warn "Config generation requires Python 3.10+ (non-fatal)"

# Generate coordinator config dir
mkdir -p "$EXAMPLE_DIR/configs/coordinator"

# Generate simulator scenario YAML
log "Generating simulator scenario..."
python3 "$EXAMPLE_DIR/simulator/generate_scenario.py" \
    "$EXAMPLE_DIR/simulator/scenario.yaml" 2>/dev/null \
    || warn "Scenario generation requires pyyaml (non-fatal)"

# Playback mode (no Docker needed)
if [ -n "$playback_file" ]; then
    log "Playback mode: replaying $playback_file at ${speed}x"
    python3 -c "
import sys; sys.path.insert(0, '$REPO_ROOT')
from autonomous_trust.evaluation.playback import PlaybackEngine
engine = PlaybackEngine('$playback_file')
engine.on_frame(lambda f: print(f'[T+{f.t:.0f}] {f.kind}: {f.payload.get(\"description\", \"\")}'))
engine.play(speed=$speed)
"
    exit 0
fi

# Clean up previous run
log "Cleaning up previous containers..."
docker compose -f "$COMPOSE_FILE" down 2>/dev/null || true

# Start
log "Starting Multi-Agency Disaster Response Demo..."
log "  Compromise mode: $compromise_mode"
docker compose -f "$COMPOSE_FILE" up -d

log ""
log "============================================="
log "  Multi-Agency Disaster Response Demo"
log "============================================="
log ""
log "  Dashboard:   http://localhost:8050"
log "  Trust Graph:  http://localhost:8000"
log "  Simulator:    http://localhost:8051"
log ""
log "  Peers: 9 (NOAA x3, USGS x2, FEMA x3, EPA x1)"
log "  Duration: ~8 minutes"
log "  Compromise: noaa-sensor-3 ($compromise_mode mode)"
log ""
log "Timeline:"
event "0:00" "Formation — NOAA, USGS, FEMA peers discover each other"
event "1:00" "Bootstrap — trust graph stabilizes"
event "2:00" "Negotiation — data-sharing agreements formed"
event "2:30" "Data Sharing — weather & seismic streams active"
event "4:00" "Compromise — noaa-sensor-3 sends falsified temperature"
event "4:30" "Detection — cross-source validation flags anomaly"
event "5:00" "Exclusion — noaa-sensor-3 reputation collapses"
event "6:00" "EPA Onboard — epa-monitor-1 joins the network"
event "7:00" "Integration — full data sharing with 9 trusted peers"
log ""
log "View logs:  docker compose -f $COMPOSE_FILE logs -f"
log "Stop:       docker compose -f $COMPOSE_FILE down"
