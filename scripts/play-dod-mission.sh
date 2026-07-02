#!/usr/bin/env bash
# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
#  Licensed under the Apache License, Version 2.0
# ******************
#
# Canned-playback launcher for the DoD squad-infiltration demo.
#
# Replays a recording captured from a live run (run-demo.sh
# --variant=dod-mission --record-to FILE) in the same Dash dashboard the
# live coordinator serves — no containers, no cluster. Meant for a laptop
# with the AutonomousTrust Python packages available (a conda/venv that has
# dash + plotly).
#
# Sets PYTHONPATH for the namespace-split AT packages and forwards everything
# to `python -m examples.dod_mission --playback`. The scenario scaling knobs
# default to the run-demo.sh defaults (4/4/3/2) — they reconstruct the
# dashboard panels and MUST match whatever produced the recording; override
# if your live run used non-defaults.
#
# Usage:
#   scripts/play-dod-mission.sh [RECORDING.json] [options]
#
# Options:
#   --squad-size N      Squad members        (default: 4)
#   --swarm-size N      Microdrones          (default: 4)
#   --sensor-count N    Leave-behind sensors (default: 3)
#   --hacked-sensors N  Hacked sensors       (default: 2)
#   --port N            Dash port            (default: 8050)
#   --speed X           1.0|2.0|5.0|10.0     (default: 1.0)
#   --no-mq800 --no-jet --no-command         Drop those roles (match the run)
#   ... any other flag (e.g. --no-auto-pause, --paused, --log-level debug)
#       is forwarded verbatim to the playback module.
#
# Presentation flow (defaults): the dashboard comes up and AUTO-PAUSES right
# before the narrative with the narration hidden; click "▶ Resume" to begin.
# Add --no-auto-pause to start playing immediately, or --speed 5.0 to skim.
#
# Examples:
#   scripts/play-dod-mission.sh                              # default file + knobs
#   scripts/play-dod-mission.sh demo.json
#   scripts/play-dod-mission.sh demo.json --speed 5.0 --no-auto-pause
#   scripts/play-dod-mission.sh rec.json --swarm-size 8 --port 8060

set -euo pipefail

# Absolute path to this script, resolved before the cd below so --help can
# read its own header regardless of the caller's working directory.
self="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/$(basename -- "${BASH_SOURCE[0]}")"

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$here"

log() { printf '[play-dod-mission] %s\n' "$*"; }
err() { printf '[play-dod-mission] ERROR: %s\n' "$*" >&2; }

# Namespace-package sources + repo root so `python -m examples.dod_mission`
# and `autonomous_trust.*` both resolve without a pip install.
export PYTHONPATH="\
$here/src/autonomous-trust:\
$here/src/autonomous-trust-evaluation:\
$here/src/autonomous-trust-inspector:\
$here/src/autonomous-trust-services:\
$here/src/autonomous-trust-simulator:\
$here${PYTHONPATH:+:$PYTHONPATH}"

PY="${PYTHON:-python3}"
command -v "$PY" >/dev/null 2>&1 || PY=python

# --- defaults (match run-demo.sh --variant=dod-mission) ------------------
RECORDING="demo.json"
SQUAD_SIZE=4
SWARM_SIZE=4
SENSOR_COUNT=3
HACKED_SENSORS=2
PORT=8050
SPEED=1.0
PASSTHRU=()        # forwarded verbatim (--no-auto-pause, --paused, --no-jet, ...)
GOT_FILE=0

while (( $# )); do
    case "$1" in
        --squad-size)      SQUAD_SIZE="$2";     shift 2;;
        --squad-size=*)    SQUAD_SIZE="${1#*=}"; shift;;
        --swarm-size)      SWARM_SIZE="$2";     shift 2;;
        --swarm-size=*)    SWARM_SIZE="${1#*=}"; shift;;
        --sensor-count)    SENSOR_COUNT="$2";   shift 2;;
        --sensor-count=*)  SENSOR_COUNT="${1#*=}"; shift;;
        --hacked-sensors)  HACKED_SENSORS="$2"; shift 2;;
        --hacked-sensors=*) HACKED_SENSORS="${1#*=}"; shift;;
        --port)            PORT="$2";           shift 2;;
        --port=*)          PORT="${1#*=}";      shift;;
        --speed)           SPEED="$2";          shift 2;;
        --speed=*)         SPEED="${1#*=}";     shift;;
        -h|--help)
            sed -n '8,46p' "$self" | sed 's/^# \{0,1\}//'
            exit 0;;
        -*)                PASSTHRU+=("$1");    shift;;   # forward unknown flags
        *)                 RECORDING="$1"; GOT_FILE=1; shift;;
    esac
done

if [[ ! -f "$RECORDING" ]]; then
    err "Recording not found: $RECORDING"
    (( GOT_FILE )) || err "    (pass the file as the first argument)"
    err "    Capture one with: scripts/run-demo.sh --variant=dod-mission --rebuild --record-to demo.json"
    exit 1
fi

# Soft dependency check — playback needs the dashboard stack.
if ! "$PY" -c "import dash, plotly" >/dev/null 2>&1; then
    err "dash/plotly not importable with '$PY'."
    err "    Activate the env that has them, e.g.: conda activate autonomous_trust"
    exit 1
fi

log "Playing $RECORDING  (squad=$SQUAD_SIZE swarm=$SWARM_SIZE sensors=$SENSOR_COUNT hacked=$HACKED_SENSORS)"
log "Dashboard: http://localhost:$PORT/   (auto-pauses before the narrative — click ▶ Resume to start)"

exec "$PY" -m examples.dod_mission \
    --playback "$RECORDING" \
    --squad-size "$SQUAD_SIZE" \
    --swarm-size "$SWARM_SIZE" \
    --sensor-count "$SENSOR_COUNT" \
    --hacked-sensors "$HACKED_SENSORS" \
    --port "$PORT" \
    --speed "$SPEED" \
    "${PASSTHRU[@]}"
