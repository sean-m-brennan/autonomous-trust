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
#
# One-command launcher for the DoD squad-infiltration demo.
#
# What it does:
#   1. Pre-flight image build: builds autonomous-trust-devel,
#      autonomous-trust-full-devel, and at-dod-mission-demo if any are
#      missing from the host docker daemon.
#   2. Regenerates examples/dod_mission/deploy/docker-compose.yml,
#      examples/dod_mission/simulator/scenario.yaml, and per-peer configs
#      from examples/dod_mission/scenario.py — honoring the scaling
#      knobs (--squad-size / --swarm-size / --sensor-count / --hacked-sensors).
#   3. Brings the stack up with `docker compose`.
#   4. Waits for the inspector dashboard on the requested port, then
#      opens a browser.
#   5. Holds the foreground; Ctrl-C tears the stack down.
#
# Examples:
#     scripts/run-demo-dod-mission.sh                      # baseline 16-peer
#     scripts/run-demo-dod-mission.sh --swarm-size=24 --sensor-count=20
#     scripts/run-demo-dod-mission.sh --compromise-mode=gradual
#     scripts/run-demo-dod-mission.sh --skip-build
#     scripts/run-demo-dod-mission.sh --clean
#
# Note on backends: this script supports docker compose only. The
# multi-agency demo also supports Tilt and Minikube; those modes are not
# yet wired for DoD (see plan §Phase 5 — scale test). The compose path
# is sufficient for everything up through ~100 peers on a single host.

set -euo pipefail

# --- Paths ---------------------------------------------------------------

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$here"

# Put namespace-package sources on PYTHONPATH so host-side python imports
# autonomous_trust.* without a pip install. Examples dir last so peer
# scripts resolve via `examples.dod_mission.*` if anything ever needs it.
AT_SRC_PATHS="$here/src/autonomous-trust:$here/src/autonomous-trust-evaluation:$here/src/autonomous-trust-inspector:$here/src/autonomous-trust-services:$here/src/autonomous-trust-simulator"
export PYTHONPATH="${AT_SRC_PATHS}:${here}${PYTHONPATH:+:$PYTHONPATH}"

EXAMPLE_DIR="$here/examples/dod_mission"
DEPLOY_DIR="$EXAMPLE_DIR/deploy"
COMPOSE_FILE="$DEPLOY_DIR/docker-compose.yml"

BASE_IMAGE="autonomous-trust-devel"
FULL_IMAGE="autonomous-trust-full-devel"
DEMO_IMAGE="at-dod-mission-demo"

INSPECTOR_PORT="${INSPECTOR_PORT:-8050}"
TRUST_GRAPH_PORT="${TRUST_GRAPH_PORT:-8000}"
SIMULATOR_PORT="${SIMULATOR_PORT:-8051}"

# Scenario knobs (matches scenario.py / generate_compose.py defaults).
SQUAD_SIZE=4
SWARM_SIZE=4
SENSOR_COUNT=3
HACKED_SENSORS=2
COMPROMISE_MODE="abrupt"
NO_BUILD=0
REBUILD=0
NO_BROWSER=0

# --- Colors / log helpers ------------------------------------------------

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()   { echo -e "${CYAN}[dod]${NC} $*"; }
warn()  { echo -e "${YELLOW}[dod]${NC} $*"; }
err()   { echo -e "${RED}[dod]${NC} $*" >&2; }
event() { echo -e "${GREEN}[T+${1}]${NC} $2"; }

# --- Argument parsing ----------------------------------------------------

usage() {
    cat <<EOF
Usage: $0 [options]

Scenario sizing:
  --squad-size N            Squad members (default: $SQUAD_SIZE)
  --swarm-size N            Microdrones (default: $SWARM_SIZE)
  --sensor-count N          Leave-behind sensors (default: $SENSOR_COUNT)
  --hacked-sensors N        Of those, how many are hacked (default: $HACKED_SENSORS)

Demo behavior:
  --compromise-mode MODE    'abrupt' | 'gradual' (default: $COMPROMISE_MODE)

Runtime:
  --skip-build              Don't (re)build docker images
  --rebuild                 Force-rebuild the demo image layer
                            (use after editing examples/dod_mission/*)
  --no-browser              Don't auto-open the dashboard
  --port PORT               Inspector port (default: $INSPECTOR_PORT)
  --clean                   Bring the stack down + drop generated configs

  -h, --help                Show this message

Environment overrides: INSPECTOR_PORT, TRUST_GRAPH_PORT, SIMULATOR_PORT

The compose YAML, simulator scenario, and per-peer configs are regenerated
on every launch from examples/dod_mission/scenario.py, so the scaling
knobs always reflect the latest values.
EOF
    exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --squad-size=*)        SQUAD_SIZE="${1#*=}";       shift;;
        --squad-size)          SQUAD_SIZE="$2";            shift 2;;
        --swarm-size=*)        SWARM_SIZE="${1#*=}";       shift;;
        --swarm-size)          SWARM_SIZE="$2";            shift 2;;
        --sensor-count=*)      SENSOR_COUNT="${1#*=}";     shift;;
        --sensor-count)        SENSOR_COUNT="$2";          shift 2;;
        --hacked-sensors=*)    HACKED_SENSORS="${1#*=}";   shift;;
        --hacked-sensors)      HACKED_SENSORS="$2";        shift 2;;
        --compromise-mode=*)   COMPROMISE_MODE="${1#*=}";  shift;;
        --compromise-mode)     COMPROMISE_MODE="$2";       shift 2;;
        --skip-build)          NO_BUILD=1;                 shift;;
        --rebuild)             REBUILD=1;                  shift;;
        --no-browser)          NO_BROWSER=1;               shift;;
        --port=*)              INSPECTOR_PORT="${1#*=}";   shift;;
        --port)                INSPECTOR_PORT="$2";        shift 2;;
        --clean)
            if [[ -f "$COMPOSE_FILE" ]]; then
                log "Bringing stack down..."
                docker compose -f "$COMPOSE_FILE" down 2>/dev/null || true
            fi
            log "Removing generated artifacts..."
            rm -f "$COMPOSE_FILE"
            rm -f "$EXAMPLE_DIR/simulator/scenario.yaml"
            rm -rf "$EXAMPLE_DIR/configs"
            log "Done."
            exit 0
            ;;
        -h|--help) usage 0;;
        *) err "Unknown option: $1"; usage 1;;
    esac
done

# --- Pre-flight ---------------------------------------------------------

command -v docker >/dev/null 2>&1 || { err "docker not found"; exit 1; }
command -v python3 >/dev/null 2>&1 || { err "python3 not found"; exit 1; }

# Build-arg plumbing for proxy-fronted sandboxes.  When the host runs
# behind an HTTPS proxy with a custom CA (typical for development
# sandboxes that route outbound traffic through host.docker.internal),
# Dockerfile-devel needs http_proxy/https_proxy + CERT_CONTENT so conda
# and apt can reach the upstream mirrors.  All of this is no-op when
# the corresponding env vars are unset.
build_args=()
[[ -n "${http_proxy:-}" ]]   && build_args+=("--build-arg" "http_proxy=${http_proxy}")
[[ -n "${https_proxy:-}" ]]  && build_args+=("--build-arg" "https_proxy=${https_proxy}")
[[ -n "${no_proxy:-}" ]]     && build_args+=("--build-arg" "no_proxy=${no_proxy}")
proxy_ca="/usr/local/share/ca-certificates/proxy-ca.crt"
if [[ -r "$proxy_ca" ]]; then
    build_args+=("--build-arg" "CERT_CONTENT=$(cat "$proxy_ca")")
fi

# Image chain — build any that are missing in the host docker daemon.
ensure_demo_images() {
    if ! docker image inspect "$BASE_IMAGE" >/dev/null 2>&1; then
        log "Building base image: $BASE_IMAGE ..."
        docker build --network host "${build_args[@]}" -t "$BASE_IMAGE" \
            -f "$here/src/autonomous-trust/Dockerfile-devel" "$here"
    fi
    if ! docker image inspect "$FULL_IMAGE" >/dev/null 2>&1; then
        log "Building full stack image: $FULL_IMAGE ..."
        docker build --network host "${build_args[@]}" -t "$FULL_IMAGE" \
            -f "$here/src/Dockerfile-devel" "$here"
    fi
    # The demo image is the thin COPY layer on top of the full-devel
    # stack; --rebuild forces it to pick up edits under
    # examples/dod_mission/ (Docker layer-cache is otherwise content-
    # addressed and skips when the COPY input hash hasn't changed in a
    # way it recognizes — and it definitely doesn't notice in-place
    # script edits when the image tag already exists).
    if (( REBUILD == 1 )) \
            || ! docker image inspect "$DEMO_IMAGE" >/dev/null 2>&1; then
        log "Building DoD mission demo image: $DEMO_IMAGE ..."
        docker build --network host "${build_args[@]}" -t "$DEMO_IMAGE" \
            -f "$DEPLOY_DIR/Dockerfile" "$here"
    fi
}

if (( NO_BUILD == 0 )); then
    ensure_demo_images
elif (( REBUILD == 1 )); then
    err "--rebuild and --skip-build are mutually exclusive."
    exit 1
elif ! docker image inspect "$DEMO_IMAGE" >/dev/null 2>&1; then
    err "Image '$DEMO_IMAGE' not found and --skip-build was set."
    err "Build the image chain first, or rerun without --skip-build."
    exit 1
fi

# --- Generation ---------------------------------------------------------

scenario_args=(
    --squad-size      "$SQUAD_SIZE"
    --swarm-size      "$SWARM_SIZE"
    --sensor-count    "$SENSOR_COUNT"
    --hacked-sensors  "$HACKED_SENSORS"
)

log "Regenerating per-peer configs..."
python3 - <<PY || warn "per-peer config generation failed (non-fatal; AT may regenerate at startup)"
import sys
sys.path.insert(0, '$here')
sys.path.insert(0, '$EXAMPLE_DIR')
from autonomous_trust.evaluation.deployment import generate_peer_configs
from scenario import DoDMissionScenario
sc = DoDMissionScenario(
    squad_size=$SQUAD_SIZE, swarm_size=$SWARM_SIZE,
    sensor_count=$SENSOR_COUNT, hacked_sensors=$HACKED_SENSORS,
)
generate_peer_configs(sc, '$EXAMPLE_DIR')
print(f'  configs written for {len(sc.peers)} peers')
PY

log "Regenerating simulator scenario.yaml..."
python3 "$EXAMPLE_DIR/simulator/generate_scenario.py" \
    "$EXAMPLE_DIR/simulator/scenario.yaml" \
    "${scenario_args[@]}" >/dev/null \
    || warn "simulator scenario generation failed (non-fatal)"

log "Regenerating docker-compose.yml..."
# Shared scenario T=0 epoch so every peer's DoDDataProcess emits
# timestamps anchored to the same wall-clock origin (the sensor-
# comparison charts need this to line up consensus across peers that
# join at different real times — sensors at T+120, MQ-800 at T+240,
# jet at T+360).  Captured here (not in generate_compose.py) so a
# `--clean` + relaunch resets t0 rather than reusing a stale epoch.
export AT_DEMO_T0_EPOCH=$(date +%s)
python3 "$DEPLOY_DIR/generate_compose.py" "$COMPOSE_FILE" \
    "${scenario_args[@]}" \
    || { err "compose generation failed"; exit 1; }

# --- Up -----------------------------------------------------------------

log "Cleaning up any previous run..."
docker compose -f "$COMPOSE_FILE" down 2>/dev/null || true

# AT_COMPROMISE_MODE is consumed by the participant container running the
# MQ-800 (see examples/dod_mission/participant.py). Exporting it here lets
# `docker compose up` inject it into the running services without having
# to regenerate the compose YAML for a mode flip.
export AT_COMPROMISE_MODE="$COMPROMISE_MODE"

log "Bringing up DoD squad infiltration stack..."
log "  Compromise mode:   $COMPROMISE_MODE"
log "  Peers:             $((SQUAD_SIZE + SWARM_SIZE + SENSOR_COUNT + 5)) total"
log "  Squad / Swarm:     $SQUAD_SIZE soldiers, $SWARM_SIZE microdrones"
log "  Sensors / Hacked:  $SENSOR_COUNT leave-behind ($HACKED_SENSORS hacked)"
docker compose -f "$COMPOSE_FILE" up -d

# --- Inspector readiness probe ------------------------------------------

wait_for_http() {
    local url="$1"
    local timeout="${2:-180}"
    local label="${3:-service}"
    local start last_progress=0 elapsed code

    if ! command -v curl >/dev/null 2>&1; then
        warn "curl not available; skipping readiness probe for $label"
        return 0
    fi
    start=$(date +%s)
    while :; do
        code=$(curl --silent --output /dev/null --max-time 2 \
                    --write-out '%{http_code}' "$url" || echo "000")
        if [[ "$code" == "200" || "$code" == "302" ]]; then
            return 0
        fi
        elapsed=$(( $(date +%s) - start ))
        if (( elapsed >= timeout )); then
            return 1
        fi
        if (( elapsed - last_progress >= 10 )); then
            warn "  ... waiting for $label (${elapsed}s, http=$code)"
            last_progress=$elapsed
        fi
        sleep 1
    done
}

open_browser() {
    local url="$1"
    if (( NO_BROWSER == 1 )); then
        log "Dashboard available at: $url"
        return
    fi
    if command -v xdg-open >/dev/null 2>&1; then
        xdg-open "$url" >/dev/null 2>&1 &
    elif command -v open >/dev/null 2>&1; then
        open "$url" >/dev/null 2>&1 &
    else
        log "Dashboard available at: $url"
    fi
}

inspector_url="http://localhost:$INSPECTOR_PORT/"
log "Waiting for inspector at $inspector_url ..."
if wait_for_http "$inspector_url" 240 "inspector"; then
    open_browser "$inspector_url"
else
    warn "Inspector did not respond within 240s; check container logs:"
    warn "    docker compose -f $COMPOSE_FILE logs -f coordinator"
fi

# --- Banner + foreground wait -------------------------------------------

echo ""
echo "============================================="
echo "  DoD Squad Infiltration Demo"
echo "============================================="
echo ""
log "  Dashboard:    http://localhost:$INSPECTOR_PORT"
log "  Trust graph:  http://localhost:$TRUST_GRAPH_PORT"
log "  Simulator:    http://localhost:$SIMULATOR_PORT"
echo ""
echo "Timeline:"
event "0:00" "Setup    — Network forms (squad + microdrones + RQ-86s + command)"
event "1:00" "Approach — Squad advances, swarm sweeps ahead"
event "2:00" "Contact  — Leave-behind sensors discovered; hacked ones rejected"
event "3:00" "Intel    — Cross-source fusion locates target"
event "4:00" "Rogue    — MQ-800 arrives, sends contradictory ISR, excluded"
event "5:00" "ECM      — RQ-86s engage rogue with countermeasures"
event "6:00" "Strike   — Fighter jet validates < 1s and fires"
event "7:00" "Exfil    — Squad withdraws with remaining microdrones"
echo ""
log "Container logs:  docker compose -f $COMPOSE_FILE logs -f"
log "Stop / cleanup:  $0 --clean"
echo ""
log "--- Running. Ctrl-C to stop ---"

# Foreground until Ctrl-C or until all containers exit on their own.
trap 'echo; log "Stopping..."; \
      docker compose -f "$COMPOSE_FILE" down' INT TERM
while docker compose -f "$COMPOSE_FILE" ps --services --filter \
        status=running 2>/dev/null | grep -q .; do
    sleep 5
done
