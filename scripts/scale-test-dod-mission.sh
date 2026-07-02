#!/usr/bin/env bash
# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
# ******************
#
# Unattended scale-test driver for the DoD mission demo. Iterates
# through configurable peer-count points; at each point regenerates
# docker-compose.yml, brings the stack up, tails the coordinator
# stdout for the key event markers, then tears the stack down. Per-
# run container logs and an overall CSV + JSON summary land under
# the chosen output directory.
#
# What gets timed (seconds from `docker compose up` returning):
#   compose_up_sec        First HTTP 200 on the dashboard port
#   first_reading_sec     First "first reading payload" line from coord
#   first_anomaly_sec     First "ANOMALY:" line from coord (validator hit
#                         on contradictory sensor data — the MQ-800
#                         compromise signal)
#   first_batch_ts_sec    First "first batch TransactionScore submitted"
#                         line (paxos round actually proposed)
#   wall_total_sec        Wall time spent under load for the run
#
# Default scale points (all three):
#   16-peer    (squad=4  swarm=4   sensor=3 hacked=2)   baseline
#   25-peer    (squad=4  swarm=16  sensor=3 hacked=2)   modest swarm
#   100-peer   (squad=4  swarm=88  sensor=3 hacked=2)   big swarm
#
# Each total = squad + swarm + sensor + 1 (mq800) + 1 (jet) +
#              1 (command) + 2 (RQ-86 pair). The 100-peer point
# is single-host-heavy: budget ~10 GB RAM and expect a slow
# compose-up (~30-60s). For an unattended overnight run, override
# MAX_WALL to give the bigger scenarios room to finish.
#
# Usage:
#   scripts/scale-test-dod-mission.sh
#   scripts/scale-test-dod-mission.sh --max-wall 600 --out-dir /tmp/dod-scale
#   scripts/scale-test-dod-mission.sh --scales \
#       "9-peer:2,4,2,1 16-peer:4,4,3,2 25-peer:4,16,3,2"
#   scripts/scale-test-dod-mission.sh --skip-build   # reuse existing images
#   scripts/scale-test-dod-mission.sh --dry-run      # just emit compose YAML
#
# Does NOT run through scripts/run-demo.sh because that script's
# compose mode hangs at an interactive watch loop. The driver invokes
# the compose generator and `docker compose` directly so each scale
# point can return programmatically.

set -euo pipefail

# --- Paths ----------------------------------------------------------------

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$here"

AT_SRC_PATHS="$here/src/autonomous-trust:$here/src/autonomous-trust-evaluation:$here/src/autonomous-trust-inspector:$here/src/autonomous-trust-services:$here/src/autonomous-trust-simulator"
export PYTHONPATH="${AT_SRC_PATHS}:${here}${PYTHONPATH:+:$PYTHONPATH}"

# Project is conda-based; the canonical interpreter lives in the
# `autonomous_trust` env (see environment.yml + scripts/setup-dev.sh).
# Match the gating convention used by scripts/build-py.sh: refuse to
# run when that env isn't active. The actual check is deferred until after
# argument parsing so that --help works without the env active.
CONDA_ENV_NAME="${CONDA_ENV_NAME:-autonomous_trust}"
# Use the env's python — once activated, plain `python` resolves
# through $CONDA_PREFIX/bin first. Override with AT_PYTHON for
# debugging only.
AT_PYTHON="${AT_PYTHON:-${CONDA_PREFIX:+$CONDA_PREFIX/bin/python}}"
AT_PYTHON="${AT_PYTHON:-python}"
# Force pure-Python AT backend when the native .so is missing/broken;
# the generators don't actually need native, but they import the
# core package which probes for it. Cheap to set unconditionally.
export AUTONOMOUS_TRUST_BACKEND="${AUTONOMOUS_TRUST_BACKEND:-python}"

COMPOSE_FILE="$here/examples/dod_mission/deploy/docker-compose.yml"
# generate_compose / generate_k8s are module-form only (relative
# import `from ..scenario import` — see
# examples/dod_mission/deploy/generate_compose.py:46). Invoke via
# `$AT_PYTHON -m examples.dod_mission.deploy.generate_compose ...`
# below; PYTHONPATH is exported at the top of this script.
GENERATE_SIM_SCENARIO="$here/examples/dod_mission/simulator/generate_scenario.py"
SIM_SCENARIO_YAML="$here/examples/dod_mission/simulator/scenario.yaml"

# --- Defaults -------------------------------------------------------------

OUT_DIR="${OUT_DIR:-$here/.scale-results}"
INSPECTOR_PORT="${INSPECTOR_PORT:-8050}"
MAX_WALL=600                            # cap per scale point, seconds
# Max concurrent container creations the docker daemon handles at
# `compose up`. Without this, 100 simultaneous creates have been
# observed to stall the daemon's filesystem layer (containers stuck
# in "Created" or compose hangs entirely). 10 is conservative and
# adds only ~15s to a 100-peer cold up vs unlimited parallel. Override
# with `--up-parallel N` or env `COMPOSE_PARALLEL_LIMIT`.
COMPOSE_PARALLEL_LIMIT="${COMPOSE_PARALLEL_LIMIT:-10}"
SKIP_BUILD=0
DRY_RUN=0
RESCRAPE=0
INSTALL_DEPS=0
SCALES_RAW=""
# Image reference used by the build chain AND written into the
# generated compose YAML. Must match between the two or compose will
# try to pull from a registry (the default generate_compose.py emits
# an unqualified `at-dod-mission-demo` ref, which docker resolves to
# `:latest` and fails the demo pull). Tracks run-demo.sh's :dev tag
# convention; override with IMAGE_TAG if you've built differently.
REGISTRY="${REGISTRY:-}"
IMAGE_TAG="${IMAGE_TAG:-:dev}"
DEMO_IMAGE_REF="${REGISTRY}at-dod-mission-demo${IMAGE_TAG}"

# --- Color + log helpers --------------------------------------------------

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'
log()   { echo -e "${CYAN}[scale]${NC} $*"; }
warn()  { echo -e "${YELLOW}[scale]${NC} $*"; }
err()   { echo -e "${RED}[scale]${NC} $*" >&2; }
ok()    { echo -e "${GREEN}[scale]${NC} $*"; }

usage() {
    cat <<EOF
Usage: $0 [options]

Drives the DoD mission demo through a sequence of peer counts and
records wall-clock budgets for each. Designed for unattended runs.

Options:
  --scales LIST          Space-separated list of
                         label:squad,swarm,sensor,hacked tuples.
                         Default: "16-peer:4,4,3,2 25-peer:4,16,3,2
                                   100-peer:4,88,3,2"
                         Pass --scales "100-peer:4,88,3,2" to skip
                         the smaller points.
  --max-wall SEC         Per-scale-point wall-time cap. Default: $MAX_WALL
  --up-parallel N        Cap on docker compose up's concurrent
                         container creations. Default: $COMPOSE_PARALLEL_LIMIT
                         (env: COMPOSE_PARALLEL_LIMIT)
  --out-dir DIR          Output dir for per-run logs + summary.
                         Default: $OUT_DIR
  --port PORT            Dashboard port to probe. Default: $INSPECTOR_PORT
  --skip-build           Don't pre-build the image chain (assumes :dev
                         tags already exist locally).
  --dry-run              Only generate the compose YAML at each scale
                         point and write summary scaffolding. Does
                         NOT invoke docker.
  --rescrape             Skip docker entirely; walk --out-dir for
                         existing per-run dirs and re-derive timings
                         from each coordinator.log. Useful for
                         re-extracting metrics after a parser fix
                         without rerunning the demo.
  --install-deps         If the active conda env is missing pyyaml,
                         install it via mamba/conda before proceeding.
  -h, --help             Show this help.

Each scale point produces:
  <out-dir>/<label>/docker-compose.yml      generated manifest
  <out-dir>/<label>/scenario.yaml           simulator scenario.yaml snapshot
  <out-dir>/<label>/coordinator.log         coordinator stdout/stderr
  <out-dir>/<label>/all.log                 all containers (compose logs)
  <out-dir>/<label>/timings.json            per-run timings

Aggregate output:
  <out-dir>/summary.csv
  <out-dir>/summary.json
EOF
    exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --scales=*)        SCALES_RAW="${1#*=}";  shift;;
        --scales)          SCALES_RAW="$2";       shift 2;;
        --max-wall=*)      MAX_WALL="${1#*=}";    shift;;
        --max-wall)        MAX_WALL="$2";         shift 2;;
        --up-parallel=*)   COMPOSE_PARALLEL_LIMIT="${1#*=}"; shift;;
        --up-parallel)     COMPOSE_PARALLEL_LIMIT="$2";      shift 2;;
        --out-dir=*)       OUT_DIR="${1#*=}";     shift;;
        --out-dir)         OUT_DIR="$2";          shift 2;;
        --port=*)          INSPECTOR_PORT="${1#*=}"; shift;;
        --port)            INSPECTOR_PORT="$2";   shift 2;;
        --skip-build)      SKIP_BUILD=1;          shift;;
        --dry-run)         DRY_RUN=1;             shift;;
        --rescrape)        RESCRAPE=1;            shift;;
        --install-deps)    INSTALL_DEPS=1;        shift;;
        -h|--help)         usage 0;;
        *) err "Unknown option: $1"; usage 1;;
    esac
done

# Enforce the conda-env gate now that --help has had a chance to short-circuit.
if [[ "${CONDA_DEFAULT_ENV:-}" != "$CONDA_ENV_NAME" ]]; then
    echo "ERROR: conda environment '$CONDA_ENV_NAME' is not active." >&2
    echo "  Run: conda activate $CONDA_ENV_NAME" >&2
    exit 1
fi

if [[ -z "$SCALES_RAW" ]]; then
    SCALES_RAW="16-peer:4,4,3,2 25-peer:4,16,3,2 100-peer:4,88,3,2"
fi

# --- Tool preflight -------------------------------------------------------

if [[ -z "$AT_PYTHON" ]] || { ! command -v "$AT_PYTHON" &>/dev/null && [[ ! -x "$AT_PYTHON" ]]; }; then
    err "python interpreter not found (AT_PYTHON=$AT_PYTHON)"
    err "    Set AT_PYTHON to a python with autonomous-trust deps installed."
    exit 1
fi
log "Using python: $AT_PYTHON"

# The compose + scenario generators import a handful of conda-installed
# deps (pyyaml at minimum; environment.yml is the canonical source).
# Probe up front so the error message points the user at the fix
# instead of producing a traceback per scale point.
ensure_py_deps() {
    local missing=()
    for mod in yaml; do
        if ! "$AT_PYTHON" -c "import $mod" 2>/dev/null; then
            missing+=("$mod")
        fi
    done
    if (( ${#missing[@]} == 0 )); then
        return 0
    fi
    # python module → conda-forge package name. Add entries here as
    # additional modules become required at scale-test time.
    local pkgs=()
    for m in "${missing[@]}"; do
        case "$m" in
            yaml) pkgs+=("pyyaml");;
            *)    pkgs+=("$m");;
        esac
    done

    if (( INSTALL_DEPS == 1 )); then
        local installer=""
        if command -v mamba &>/dev/null; then
            installer="mamba"
        elif command -v conda &>/dev/null; then
            installer="conda"
        else
            err "Missing deps in $CONDA_ENV_NAME env: ${missing[*]}"
            err "    Neither mamba nor conda on PATH. Activate the env"
            err "    properly (conda activate $CONDA_ENV_NAME) or install"
            err "    manually:"
            err "    conda install -n $CONDA_ENV_NAME -c conda-forge ${pkgs[*]}"
            exit 1
        fi
        log "Installing missing deps via $installer into $CONDA_ENV_NAME: ${pkgs[*]}"
        $installer install -n "$CONDA_ENV_NAME" -c conda-forge -y \
            "${pkgs[@]}" >/dev/null
        return
    fi
    err "Missing python deps in $CONDA_ENV_NAME env: ${missing[*]}"
    err "    Re-run with --install-deps, OR install them manually:"
    err "    mamba install -n $CONDA_ENV_NAME -c conda-forge ${pkgs[*]}"
    err "    (or: conda env update -n $CONDA_ENV_NAME --file environment.yml)"
    exit 1
}
ensure_py_deps

if (( DRY_RUN == 0 && RESCRAPE == 0 )); then
    command -v docker &>/dev/null || { err "docker not found"; exit 1; }
    command -v curl   &>/dev/null || { err "curl not found";   exit 1; }
fi

mkdir -p "$OUT_DIR"
SUMMARY_CSV="$OUT_DIR/summary.csv"
SUMMARY_JSON="$OUT_DIR/summary.json"

cat >"$SUMMARY_CSV" <<EOF
label,squad,swarm,sensor,hacked,total_peers,compose_up_sec,first_reading_sec,first_anomaly_sec,first_batch_ts_sec,wall_total_sec,status,error
EOF

# Build JSON in a tmp file we accumulate to, then close out at the end.
JSON_RUNS_FILE=$(mktemp)
trap 'rm -f "$JSON_RUNS_FILE"' EXIT
echo "" >"$JSON_RUNS_FILE"

# --- Helpers --------------------------------------------------------------

# Bring the compose stack down idempotently. Safe to call repeatedly.
stack_down() {
    if [[ -f "$COMPOSE_FILE" ]]; then
        docker compose -f "$COMPOSE_FILE" down \
            --remove-orphans --volumes 2>/dev/null || true
    fi
}

# Build image chain via run-demo.sh's preflight path. Only the docker
# steps; we don't actually launch via run-demo because it owns an
# interactive trap/watch loop.
build_images_once() {
    if (( SKIP_BUILD == 1 )); then
        log "Skipping image build (--skip-build)"
        return
    fi
    log "Pre-building image chain (one-time; reused across scale points) ..."
    # Use run-demo.sh in --teardown mode just to drive its image-check
    # logic? No — --teardown skips the build path. The easiest reuse is
    # to invoke run-demo's compose generator step in --skip-build mode,
    # but compose mode does its own up. Cleanest: shell out to docker
    # build directly here, matching run-demo's chain.
    local base="${REGISTRY}autonomous-trust${IMAGE_TAG}"
    local inspector="${REGISTRY}autonomous-trust-inspector${IMAGE_TAG}"
    local demo="$DEMO_IMAGE_REF"
    local peer="${REGISTRY}at-dod-mission-peer${IMAGE_TAG}"
    if ! docker image inspect "$base" &>/dev/null; then
        log "  building $base"
        docker build --network host -t "$base" \
            -f "$here/src/autonomous-trust/Dockerfile-native" "$here"
    fi
    if ! docker image inspect "$inspector" &>/dev/null; then
        log "  building $inspector"
        docker build --network host --build-arg "BASE_IMAGE=$base" \
            -t "$inspector" \
            -f "$here/src/autonomous-trust-inspector/Dockerfile" "$here"
    fi
    if ! docker image inspect "$demo" &>/dev/null; then
        log "  building $demo"
        docker build --network host --build-arg "BASE_IMAGE=$inspector" \
            -t "$demo" \
            -f "$here/examples/dod_mission/deploy/Dockerfile" "$here"
    fi
    if ! docker image inspect "$peer" &>/dev/null; then
        log "  building $peer"
        docker build --network host --build-arg "BASE_IMAGE=$base" \
            -t "$peer" \
            -f "$here/examples/dod_mission/deploy/Dockerfile-peer" "$here"
    fi
}

# Regenerate the per-peer compose YAML + simulator scenario.yaml for a
# given scale point. Mirrors what scripts/run-demo.sh does on `--compose`.
regenerate_manifests() {
    local squad=$1 swarm=$2 sensor=$3 hacked=$4
    AT_DEMO_T0_EPOCH=$(date +%s) $AT_PYTHON \
        -m examples.dod_mission.deploy.generate_compose \
        "$COMPOSE_FILE" \
        --image "$DEMO_IMAGE_REF" \
        --squad-size "$squad" \
        --swarm-size "$swarm" \
        --sensor-count "$sensor" \
        --hacked-sensors "$hacked" >/dev/null
    # Simulator scenario regeneration is best-effort: it transitively
    # imports geopy + a few other deps that aren't strictly required
    # for `docker compose up` (the previous scenario.yaml stays bind-
    # mounted from the host). Match run-demo.sh's `|| warn` pattern.
    if ! $AT_PYTHON "$GENERATE_SIM_SCENARIO" "$SIM_SCENARIO_YAML" \
            --squad-size "$squad" \
            --swarm-size "$swarm" \
            --sensor-count "$sensor" \
            --hacked-sensors "$hacked" >/dev/null 2>&1; then
        warn "  simulator scenario regeneration failed (non-fatal)"
    fi
}

# Block until http://localhost:$PORT/ returns 200/302 or until timeout.
# Echoes elapsed seconds (float) on success, empty on timeout.
wait_for_http() {
    local timeout="$1"
    local start now elapsed code
    start=$(date +%s.%N)
    while :; do
        code=$(curl --silent --output /dev/null --max-time 2 \
                    --write-out '%{http_code}' \
                    "http://localhost:$INSPECTOR_PORT/" 2>/dev/null \
               || echo 000)
        code=${code:-000}
        if [[ "$code" == "200" || "$code" == "302" ]]; then
            now=$(date +%s.%N)
            $AT_PYTHON -c "print(round($now - $start, 2))"
            return 0
        fi
        elapsed=$($AT_PYTHON -c "print($(date +%s.%N) - $start)")
        if $AT_PYTHON -c "exit(0 if $elapsed >= $timeout else 1)"; then
            return 1
        fi
        sleep 1
    done
}

# Search a per-run coordinator log for marker patterns. For each
# pattern, echo the seconds-since-up at which the line first appeared
# (or empty if not seen yet). The driver calls this repeatedly while
# the run is live.
elapsed_for_pattern() {
    local file="$1" pattern="$2" t_start="$3"
    # `docker compose logs -f` prefixes every line with the service
    # name + " | " (e.g. `dod-mission-coordinator  | 2026-05-27 ...
    # WARNING ...: ANOMALY: ...`). The timestamp lives AFTER that
    # prefix, so we use re.search (not re.match) so it can be found
    # mid-line. Patterns supplied by callers should likewise not be
    # anchored at start-of-line.
    grep -m1 -E "$pattern" "$file" 2>/dev/null | \
        $AT_PYTHON -c "
import sys, re, datetime as dt
line = sys.stdin.read().strip()
if not line:
    sys.exit(1)
m = re.search(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d+)', line)
if not m:
    sys.exit(1)
t = dt.datetime.strptime(m.group(1).replace(',', '.'),
                         '%Y-%m-%d %H:%M:%S.%f').timestamp()
print(round(t - $t_start, 2))
" 2>/dev/null
}

# Run one scale point end-to-end. Returns 0 on a clean run, non-zero on
# failure. Always tears down the stack on exit.
run_scale_point() {
    local label="$1" squad="$2" swarm="$3" sensor="$4" hacked="$5"
    local run_dir="$OUT_DIR/$label"
    mkdir -p "$run_dir"

    log "[$label] squad=$squad swarm=$swarm sensor=$sensor hacked=$hacked"

    regenerate_manifests "$squad" "$swarm" "$sensor" "$hacked"
    cp "$COMPOSE_FILE" "$run_dir/docker-compose.yml"
    [[ -f "$SIM_SCENARIO_YAML" ]] && \
        cp "$SIM_SCENARIO_YAML" "$run_dir/scenario.yaml"

    # Total peer count from the generated compose (peers + sim + coord).
    local total_peers
    total_peers=$($AT_PYTHON -c "
import yaml
with open('$COMPOSE_FILE') as f: d = yaml.safe_load(f)
# Minus simulator + coordinator
print(len(d.get('services', {})) - 2)
")

    if (( DRY_RUN == 1 )); then
        log "[$label] dry-run: wrote $run_dir/docker-compose.yml (peers=$total_peers)"
        local timings='{"compose_up_sec":null,"first_reading_sec":null,"first_anomaly_sec":null,"first_batch_ts_sec":null,"wall_total_sec":null}'
        printf '%s,%s,%s,%s,%s,%s,,,,,,dry-run,\n' \
            "$label" "$squad" "$swarm" "$sensor" "$hacked" "$total_peers" \
            >>"$SUMMARY_CSV"
        printf '%s{"label":"%s","scenario":{"squad_size":%s,"swarm_size":%s,"sensor_count":%s,"hacked_sensors":%s},"total_peers":%s,"timings":%s,"status":"dry-run","error":""}' \
            "$( [[ $(wc -c <"$JSON_RUNS_FILE") -gt 1 ]] && echo "," )" \
            "$label" "$squad" "$swarm" "$sensor" "$hacked" \
            "$total_peers" "$timings" >>"$JSON_RUNS_FILE"
        return 0
    fi

    # Reap any prior run.
    stack_down

    local up_start
    up_start=$(date +%s.%N)
    # Throttle docker compose's daemon-call concurrency via the env
    # variable (portable back to compose v2.0). The `--parallel` flag
    # on `up` only appeared in newer compose versions and errors out
    # on older ones with "unknown flag: --parallel".
    log "[$label] docker compose up -d (COMPOSE_PARALLEL_LIMIT=$COMPOSE_PARALLEL_LIMIT) ..."
    if ! COMPOSE_PARALLEL_LIMIT="$COMPOSE_PARALLEL_LIMIT" \
            docker compose -f "$COMPOSE_FILE" up -d \
            >"$run_dir/compose-up.log" 2>&1; then
        warn "[$label] compose up failed (see $run_dir/compose-up.log)"
        local timings='{"compose_up_sec":null,"first_reading_sec":null,"first_anomaly_sec":null,"first_batch_ts_sec":null,"wall_total_sec":null}'
        printf '%s,%s,%s,%s,%s,%s,,,,,,error,compose-up-failed\n' \
            "$label" "$squad" "$swarm" "$sensor" "$hacked" "$total_peers" \
            >>"$SUMMARY_CSV"
        printf '%s{"label":"%s","total_peers":%s,"timings":%s,"status":"error","error":"compose-up-failed"}' \
            "$( [[ $(wc -c <"$JSON_RUNS_FILE") -gt 1 ]] && echo "," )" \
            "$label" "$total_peers" "$timings" >>"$JSON_RUNS_FILE"
        stack_down
        return 1
    fi
    local t_start
    t_start=$(date +%s.%N)

    # Tail coordinator stdout to a per-run log. `docker compose logs -f`
    # starts streaming immediately for whatever's running; race that
    # against the container actually being up is benign because the
    # tail blocks gracefully.
    docker compose -f "$COMPOSE_FILE" logs -f --no-color coordinator \
        >"$run_dir/coordinator.log" 2>&1 &
    local coord_pid=$!

    # Also tail the whole stack into all.log so we can post-mortem
    # any peer-side failure without re-running.
    docker compose -f "$COMPOSE_FILE" logs -f --no-color \
        >"$run_dir/all.log" 2>&1 &
    local all_pid=$!

    log "[$label] waiting for inspector at http://localhost:$INSPECTOR_PORT/ (cap ${MAX_WALL}s) ..."
    local compose_up_sec=""
    if compose_up_sec=$(wait_for_http "$MAX_WALL"); then
        ok "[$label] inspector up at +${compose_up_sec}s"
    else
        warn "[$label] inspector did not respond within ${MAX_WALL}s"
    fi

    # Now poll the coordinator log file for the event markers. We loop
    # at 5s cadence, recording the elapsed time at which each marker
    # first appears. Bail early once all three have been seen.
    local first_reading_sec="" first_anomaly_sec="" first_batch_ts_sec=""
    local poll_until
    poll_until=$($AT_PYTHON -c "print($t_start + $MAX_WALL)")
    while :; do
        local now_t
        now_t=$(date +%s.%N)
        if $AT_PYTHON -c "exit(0 if $now_t >= $poll_until else 1)"; then
            break
        fi
        if [[ -z "$first_reading_sec" ]]; then
            first_reading_sec=$(elapsed_for_pattern \
                "$run_dir/coordinator.log" \
                "first reading payload from" "$t_start" || true)
        fi
        if [[ -z "$first_anomaly_sec" ]]; then
            # `ANOMALY:` is emitted by coordinator.py's validator hit
            # logger.warning; matches anywhere in the docker-compose-
            # prefixed line (`dod-mission-coordinator | ... ANOMALY: ...`).
            first_anomaly_sec=$(elapsed_for_pattern \
                "$run_dir/coordinator.log" \
                "ANOMALY:" "$t_start" || true)
        fi
        if [[ -z "$first_batch_ts_sec" ]]; then
            first_batch_ts_sec=$(elapsed_for_pattern \
                "$run_dir/coordinator.log" \
                "first batch TransactionScore submitted" "$t_start" || true)
        fi
        if [[ -n "$first_reading_sec" && -n "$first_anomaly_sec" \
              && -n "$first_batch_ts_sec" ]]; then
            ok "[$label] all markers fired; stopping early"
            break
        fi
        sleep 5
    done

    # Tear down. Log-tails die when compose stops.
    log "[$label] tearing down ..."
    stack_down
    kill "$coord_pid" 2>/dev/null || true
    kill "$all_pid"   2>/dev/null || true
    wait "$coord_pid" 2>/dev/null || true
    wait "$all_pid"   2>/dev/null || true

    local wall_total_sec
    wall_total_sec=$($AT_PYTHON -c "print(round($(date +%s.%N) - $up_start, 2))")

    local status="ok" errmsg=""
    if [[ -z "$compose_up_sec" ]]; then
        status="degraded"; errmsg="inspector-timeout"
    elif [[ -z "$first_anomaly_sec" ]]; then
        status="degraded"; errmsg="no-anomaly-within-${MAX_WALL}s"
    fi

    # Per-run timings.json (handy when summary.json gets unwieldy).
    cat >"$run_dir/timings.json" <<EOF
{
  "label": "$label",
  "scenario": {
    "squad_size": $squad,
    "swarm_size": $swarm,
    "sensor_count": $sensor,
    "hacked_sensors": $hacked
  },
  "total_peers": $total_peers,
  "timings": {
    "compose_up_sec":      ${compose_up_sec:-null},
    "first_reading_sec":   ${first_reading_sec:-null},
    "first_anomaly_sec":   ${first_anomaly_sec:-null},
    "first_batch_ts_sec":  ${first_batch_ts_sec:-null},
    "wall_total_sec":      $wall_total_sec
  },
  "status": "$status",
  "error":  "$errmsg"
}
EOF

    printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
        "$label" "$squad" "$swarm" "$sensor" "$hacked" "$total_peers" \
        "${compose_up_sec:-}" "${first_reading_sec:-}" \
        "${first_anomaly_sec:-}" "${first_batch_ts_sec:-}" \
        "$wall_total_sec" "$status" "$errmsg" >>"$SUMMARY_CSV"

    local prefix=""
    [[ $(wc -c <"$JSON_RUNS_FILE") -gt 1 ]] && prefix=","
    cat >>"$JSON_RUNS_FILE" <<EOF
${prefix}{"label":"$label","scenario":{"squad_size":$squad,"swarm_size":$swarm,"sensor_count":$sensor,"hacked_sensors":$hacked},"total_peers":$total_peers,"timings":{"compose_up_sec":${compose_up_sec:-null},"first_reading_sec":${first_reading_sec:-null},"first_anomaly_sec":${first_anomaly_sec:-null},"first_batch_ts_sec":${first_batch_ts_sec:-null},"wall_total_sec":$wall_total_sec},"status":"$status","error":"$errmsg"}
EOF

    if [[ "$status" == "ok" ]]; then
        ok "[$label] done: up=${compose_up_sec}s reading=${first_reading_sec:-?}s anomaly=${first_anomaly_sec:-?}s ts=${first_batch_ts_sec:-?}s"
    else
        warn "[$label] $status: $errmsg"
    fi
}

# Re-derive timings from an already-captured coordinator.log. Used by
# --rescrape: walks $OUT_DIR for per-run directories and rewrites
# their timings.json + the aggregate summary, without touching docker.
#
# `t_start` for elapsed-time math is the timestamp of the first log
# line we can parse. That's an approximation of "compose up returned"
# — fine for relative measurements but compose_up_sec stays null
# because the original anchor was wall-clock from outside the log.
rescrape_run_point() {
    local label="$1"
    local run_dir="$OUT_DIR/$label"
    local coord_log="$run_dir/coordinator.log"
    if [[ ! -f "$coord_log" ]]; then
        warn "[$label] no coordinator.log in $run_dir; skipping"
        return 0
    fi

    # Recover scenario metadata from an existing timings.json if we
    # wrote one before. If not, leave the scenario fields null and
    # carry on — the timings are still useful even without the
    # peer-count breakdown.
    local squad="" swarm="" sensor="" hacked="" total_peers=""
    if [[ -f "$run_dir/timings.json" ]]; then
        # Tiny one-shot extractor — keeps us away from jq's
        # availability question.
        local meta
        meta=$($AT_PYTHON -c "
import json, sys
with open('$run_dir/timings.json') as f:
    d = json.load(f)
sc = d.get('scenario') or {}
print('%s %s %s %s %s' % (
    sc.get('squad_size', ''), sc.get('swarm_size', ''),
    sc.get('sensor_count', ''), sc.get('hacked_sensors', ''),
    d.get('total_peers', '')))
" 2>/dev/null || echo "")
        if [[ -n "$meta" ]]; then
            IFS=' ' read -r squad swarm sensor hacked total_peers <<< "$meta"
        fi
    fi

    # First log-line timestamp → synthetic t_start.
    local t_start
    t_start=$($AT_PYTHON -c "
import re, datetime as dt
ts_re = re.compile(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d+)')
with open('$coord_log') as f:
    for line in f:
        m = ts_re.search(line)
        if m:
            t = dt.datetime.strptime(
                m.group(1).replace(',', '.'),
                '%Y-%m-%d %H:%M:%S.%f').timestamp()
            print(t)
            break
" 2>/dev/null)
    if [[ -z "$t_start" ]]; then
        warn "[$label] no parseable timestamps in coordinator.log"
        return 0
    fi

    local first_reading_sec first_anomaly_sec first_batch_ts_sec
    first_reading_sec=$(elapsed_for_pattern \
        "$coord_log" "first reading payload from" "$t_start" || true)
    first_anomaly_sec=$(elapsed_for_pattern \
        "$coord_log" "ANOMALY:" "$t_start" || true)
    first_batch_ts_sec=$(elapsed_for_pattern \
        "$coord_log" "first batch TransactionScore submitted" "$t_start" || true)

    local status="ok" errmsg=""
    if [[ -z "$first_anomaly_sec" ]]; then
        status="degraded"; errmsg="no-anomaly-in-log"
    fi

    cat >"$run_dir/timings.json" <<EOF
{
  "label": "$label",
  "scenario": {
    "squad_size":     ${squad:-null},
    "swarm_size":     ${swarm:-null},
    "sensor_count":   ${sensor:-null},
    "hacked_sensors": ${hacked:-null}
  },
  "total_peers": ${total_peers:-null},
  "timings": {
    "compose_up_sec":      null,
    "first_reading_sec":   ${first_reading_sec:-null},
    "first_anomaly_sec":   ${first_anomaly_sec:-null},
    "first_batch_ts_sec":  ${first_batch_ts_sec:-null},
    "wall_total_sec":      null
  },
  "status": "$status",
  "error":  "$errmsg",
  "source": "rescrape"
}
EOF

    printf '%s,%s,%s,%s,%s,%s,,%s,%s,%s,,%s,%s\n' \
        "$label" "${squad:-}" "${swarm:-}" "${sensor:-}" "${hacked:-}" \
        "${total_peers:-}" \
        "${first_reading_sec:-}" "${first_anomaly_sec:-}" \
        "${first_batch_ts_sec:-}" \
        "$status" "$errmsg" >>"$SUMMARY_CSV"

    local prefix=""
    [[ $(wc -c <"$JSON_RUNS_FILE") -gt 1 ]] && prefix=","
    cat >>"$JSON_RUNS_FILE" <<EOF
${prefix}{"label":"$label","scenario":{"squad_size":${squad:-null},"swarm_size":${swarm:-null},"sensor_count":${sensor:-null},"hacked_sensors":${hacked:-null}},"total_peers":${total_peers:-null},"timings":{"compose_up_sec":null,"first_reading_sec":${first_reading_sec:-null},"first_anomaly_sec":${first_anomaly_sec:-null},"first_batch_ts_sec":${first_batch_ts_sec:-null},"wall_total_sec":null},"status":"$status","error":"$errmsg","source":"rescrape"}
EOF

    if [[ "$status" == "ok" ]]; then
        ok "[$label] rescrape: reading=${first_reading_sec:-?}s anomaly=${first_anomaly_sec:-?}s ts=${first_batch_ts_sec:-?}s"
    else
        warn "[$label] rescrape $status: $errmsg"
    fi
}

# --- Cleanup on signal ----------------------------------------------------

trap 'echo; warn "Interrupted; tearing down..."; stack_down; exit 130' INT TERM

# --- Main loop ------------------------------------------------------------

if (( RESCRAPE == 1 )); then
    log "Rescrape mode: re-deriving timings from $OUT_DIR"
    shopt -s nullglob
    found=0
    for run_dir in "$OUT_DIR"/*/; do
        [[ -d "$run_dir" ]] || continue
        label=$(basename "$run_dir")
        # Skip non-run subdirs.
        [[ -f "$run_dir/coordinator.log" ]] || continue
        rescrape_run_point "$label"
        found=$((found + 1))
    done
    shopt -u nullglob
    if (( found == 0 )); then
        warn "No per-run dirs with coordinator.log under $OUT_DIR"
    fi
else

(( DRY_RUN == 1 )) && log "Dry-run mode: no docker invocations"
(( DRY_RUN == 0 )) && build_images_once

# Read scales into an array.
read -r -a SCALES <<< "$SCALES_RAW"
log "Scale points: ${#SCALES[@]} (${SCALES[*]})"
log "Output:       $OUT_DIR"

for tuple in "${SCALES[@]}"; do
    label="${tuple%%:*}"
    rest="${tuple#*:}"
    IFS=',' read -r squad swarm sensor hacked <<< "$rest"
    if [[ -z "$label" || -z "$squad" || -z "$swarm" \
          || -z "$sensor" || -z "$hacked" ]]; then
        err "malformed scale spec: $tuple"
        err "    expected label:squad,swarm,sensor,hacked"
        exit 1
    fi
    run_scale_point "$label" "$squad" "$swarm" "$sensor" "$hacked"
done

fi  # rescrape branch close

# Close out summary.json.
{
    echo "{"
    echo "  \"generated_at\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\","
    echo "  \"runs\": ["
    cat "$JSON_RUNS_FILE"
    echo ""
    echo "  ]"
    echo "}"
} >"$SUMMARY_JSON"

ok "All done."
log "  CSV:  $SUMMARY_CSV"
log "  JSON: $SUMMARY_JSON"
