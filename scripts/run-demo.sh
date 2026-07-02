#!/usr/bin/env bash
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
# Unified launcher for AutonomousTrust demos. Was three scripts
# (run-demo.sh, run-demo-multi-agency.sh, run-demo-dod-mission.sh);
# generalized from the multi-agency launcher so the same arg-parsing,
# helpers, and backend dispatch cover every demo.
#
# Variants (--variant=<name>; defaults to python for backward compat):
#   python        Multi-node Python demo. CFFI-backed by default;
#                 --backend=python (or --python) switches to pure
#                 Python via Dockerfile-lite.
#   c             Multi-node pure-C demo (no Python in containers).
#   multi-agency  Disaster-response k8s scenario (peer agencies +
#                 inspector dashboard).
#   dod-mission   DoD squad-infiltration k8s scenario (coordinator,
#                 simulator service pod, and squad/swarm/sensor peers).
#
# Backends (--<mode>; allowed set varies by variant):
#   --tilt        (default) Tilt-managed; live rebuild on save.
#   --compose     docker compose (one-shot). Not for python/c — Tilt
#                 already drives gen_compose.py + docker_compose() for
#                 those.
#   --k8s         Minikube + kubectl apply (one-shot). Multi-agency
#                 and dod-mission.
#   --playback FILE  Inspector-only replay (multi-agency only).
#   --record FILE    Inspector-only scripted run, captures events
#                    (multi-agency only). For dod-mission, record a *live*
#                    run instead with --record-to FILE (see dod-mission opts).
#   --teardown    Stop a previous run + clean up, exit.
#
# Examples:
#   scripts/run-demo.sh                                 # python, tilt (default)
#   scripts/run-demo.sh --python -v 4                   # pure-Python backend, 4 nodes, info
#   scripts/run-demo.sh --variant=c -vv                 # pure-C demo, debug logs
#   scripts/run-demo.sh --variant=multi-agency          # disaster response, tilt
#   scripts/run-demo.sh --variant=multi-agency --compose
#   scripts/run-demo.sh --variant=multi-agency --playback recording.json
#   scripts/run-demo.sh --variant=dod-mission --swarm-size=8
#   scripts/run-demo.sh --variant=dod-mission --compose --record-to demo.json
#   scripts/run-demo.sh --variant=multi-agency --teardown

set -euo pipefail

# --- Paths ---------------------------------------------------------------

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$here"

# Namespace-package sources on PYTHONPATH so host-side python imports
# autonomous_trust.* without a pip install. Repo root last so example
# entrypoints resolve via `python -m examples.<name>` AND
# `python -m examples.<name>.deploy.<x>`.
AT_SRC_PATHS="$here/src/autonomous-trust:$here/src/autonomous-trust-evaluation:$here/src/autonomous-trust-inspector:$here/src/autonomous-trust-services:$here/src/autonomous-trust-simulator"
export PYTHONPATH="${AT_SRC_PATHS}:${here}${PYTHONPATH:+:$PYTHONPATH}"

# Force native backend on the host so it matches peer containers; the
# core redirector still falls back to _python per module if needed.
export AUTONOMOUS_TRUST_BACKEND="${AUTONOMOUS_TRUST_BACKEND:-native}"

# --- Variant-agnostic defaults --------------------------------------------

VARIANT="${VARIANT:-python}"
BACKEND_MODE="tilt"
LOG_LEVEL="${LOG_LEVEL:-info}"
NO_BROWSER=0
NO_BUILD=0
REBUILD=0
NUM_NODES=2
PY_BACKEND="native"                  # python variant only
NAMESPACE=""                         # set per variant below
INSPECTOR_PORT="${INSPECTOR_PORT:-8050}"
DEPLOY_DIR=""                        # set per variant below
TILT_LOG=""                          # set per variant below
REGISTRY="${REGISTRY:-}"
IMAGE_TAG="${IMAGE_TAG:-:dev}"
IMAGE_NAME="${IMAGE_NAME:-autonomous-trust}"
PLAYBACK_FILE=""                     # multi-agency only
RECORD_FILE=""                       # multi-agency only (inspector-only mode)
RECORD_TO=""                         # dod-mission: record a live run to a file

# DoD scenario knobs (only honored when --variant=dod-mission).
SQUAD_SIZE=4
SWARM_SIZE=4
SENSOR_COUNT=3
HACKED_SENSORS=2
COMPROMISE_MODE="abrupt"
# Which microdrones run the embedded C at_demo node (dod-mission + --compose
# only). "" = none (all-Python, the default); "all" = every microdrone-*; or a
# comma-list of peer names. Threaded identically to seed_dod_cohort.py and
# generate_compose.py so the seeded identity format matches the runtime.
C_MICRODRONES="${AT_C_MICRODRONES:-}"

# Probes shared volume defaults to ON for multi-agency compose.
export AT_PROBES="${AT_PROBES:-1}"

# --- Color + log helpers --------------------------------------------------

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'
log()   { echo -e "${CYAN}[$VARIANT]${NC} $*"; }
warn()  { echo -e "${YELLOW}[$VARIANT]${NC} $*"; }
err()   { echo -e "${RED}[$VARIANT]${NC} $*" >&2; }
event() { echo -e "${GREEN}[T+${1}]${NC} $2"; }

# Force-reseed cleanup. The demo containers run as root and create var/at/ (and
# the C nodes' etc/at network/subsystems configs) as root, so the Python seeder
# — running as the host user — cannot unlink that runtime state. It then
# survives a --reseed wipe, leaving stale identity/group/reputation state that
# mismatches the freshly-seeded etc/at (peers fail to re-form the cohort). Wipe
# the whole state dir as root via a throwaway container so the seed starts
# clean. Best-effort: if docker can't do it, the seeder's own partial wipe still
# runs (it skips, rather than crashes on, the undeletable files).
reseed_wipe_state() {
    local state_dir="$1"
    [[ -d "$state_dir" ]] || return 0
    log "Reseed: wiping persistent state as root via docker ($state_dir) ..."
    # sh -c so the glob expands INSIDE the container; `docker run ... rm /s/*`
    # would let the host shell expand /s/* (a nonexistent host path) and pass it
    # literally to rm, which -f-ignores it (a silent no-op). Include dotfiles;
    # `|| true` so an already-empty dir isn't a failure.
    docker run --rm -v "$state_dir:/s" alpine \
        sh -c 'rm -rf /s/* /s/.[!.]* 2>/dev/null || true' \
        || warn "Reseed root-wipe via docker failed; seeder falls back to a" \
                "partial wipe (root-owned var/at may persist)."
}

# --- Usage ----------------------------------------------------------------

usage() {
    cat <<EOF
Usage: $0 [--variant=<name>] [options] [NUM_NODES]

Variants:
  --variant=python       (default) Multi-node Python demo
  --variant=c            Multi-node pure-C demo
  --variant=multi-agency Disaster-response scenario (k8s)
  --variant=dod-mission  DoD squad-infiltration scenario (k8s)

  --python | --py        Shortcut for --variant=python --backend=python
                         (pure-Python build; default is CFFI)

Backends (pick one, defaults to --tilt; not all valid for every variant):
  --tilt                 Tilt-managed (live rebuild on save)
  --compose              docker compose (one-shot)
  --k8s                  Minikube + kubectl (multi-agency + dod-mission)
  --playback FILE        Inspector-only replay (multi-agency only)
  --record FILE          Inspector-only scripted run (multi-agency only)
  --teardown             Stop a previous run, exit
  --clean                Remove generated artifacts, exit

Common options:
  --namespace NS         K8s namespace (multi-agency/dod-mission only)
  --port PORT            Inspector port (default: $INSPECTOR_PORT)
  --log-level LEVEL      info | debug | warning (default: $LOG_LEVEL)
  --registry PREFIX      Image registry (include trailing /)
  --image-tag TAG        Image tag, include leading : (default: $IMAGE_TAG)
  --deploy-dir DIR       Output dir for generated files
  --no-browser           Don't auto-open the dashboard
  --skip-build           Don't (re)build images
  --rebuild              Force rebuild of the whole image chain (base,
                         inspector, and overlays) so edited source
                         propagates. Layer-cached, so unchanged layers
                         are near-free; only changed COPYs rebuild.
  --reseed               Force-regenerate the persistent-cohort seed
                         (fresh identities + gateway child groups);
                         same as AT_PRESEED_FORCE=1
  --no-seed              Skip seeding; all peers cold-bootstrap
                         (same as AT_PRESEED=0)
  -h, --help             Show this message

python/c options:
  -v|-vv|-vvv            Increase log verbosity (info|debug|verbose)
  NUM_NODES              Positional; nodes to start (default: $NUM_NODES)
  --backend BACKEND      CFFI-native|python (python variant only; default: native)

dod-mission options:
  --squad-size N         Squad members (default: $SQUAD_SIZE)
  --swarm-size N         Microdrones (default: $SWARM_SIZE)
  --sensor-count N       Sensors (default: $SENSOR_COUNT)
  --hacked-sensors N     Hacked sensors (default: $HACKED_SENSORS)
  --compromise-mode M    abrupt|gradual (default: $COMPROMISE_MODE)
  --c-microdrones[=SPEC] Run microdrones as embedded C at_demo nodes instead of
                         Python (requires --compose). SPEC is 'all' (default
                         when given bare), a bare integer N for the first N
                         microdrones (N < total => a MIXED Python+C swarm, e.g.
                         --c-microdrones=2), or a comma-list of peer names
                         (e.g. microdrone-1,microdrone-2). (Note: '1' means the
                         first one, not all — use 'all'.) Builds the
                         autonomous-trust-c image (Dockerfile-c, needs network
                         for apt) and seeds those peers with C-format identities
                         so they cold-join the Python mesh for the group key.
  --record-to FILE       Record this live run for canned playback. The
                         coordinator flushes FILE on graceful shutdown
                         (compose: ./recording/FILE beside the compose file;
                         k8s: on the node). Play back with
                         'python -m examples.dod_mission --playback FILE'.

Environment overrides: VARIANT, NAMESPACE, INSPECTOR_PORT, DEPLOY_DIR,
                       REGISTRY, IMAGE_TAG, LOG_LEVEL, TILT_LOG,
                       AT_RECORD, AT_RECORD_HOST_DIR, AT_RECORD_NODE_PATH
EOF
    exit "${1:-0}"
}

# --- Argument parsing -----------------------------------------------------

POSITIONAL_ARGS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --variant=*)             VARIANT="${1#*=}";          shift;;
        --variant)               VARIANT="$2";               shift 2;;
        --python|--py)           VARIANT="python"; PY_BACKEND="python"; shift;;
        --tilt)                  BACKEND_MODE="tilt";        shift;;
        --compose)               BACKEND_MODE="compose";     shift;;
        --k8s)                   BACKEND_MODE="k8s";         shift;;
        --teardown)              BACKEND_MODE="teardown";    shift;;
        --clean)                 BACKEND_MODE="clean";       shift;;
        --playback)              BACKEND_MODE="playback"; PLAYBACK_FILE="$2"; shift 2;;
        --record)                BACKEND_MODE="record";   RECORD_FILE="$2";   shift 2;;
        --record-to=*)           RECORD_TO="${1#*=}";        shift;;
        --record-to)             RECORD_TO="$2";             shift 2;;
        --namespace=*)           NAMESPACE="${1#*=}";        shift;;
        --namespace)             NAMESPACE="$2";             shift 2;;
        --port=*)                INSPECTOR_PORT="${1#*=}";   shift;;
        --port)                  INSPECTOR_PORT="$2";        shift 2;;
        --log-level=*)           LOG_LEVEL="${1#*=}";        shift;;
        --log-level)             LOG_LEVEL="$2";             shift 2;;
        --registry=*)            REGISTRY="${1#*=}";         shift;;
        --registry)              REGISTRY="$2";              shift 2;;
        --image-tag=*)           IMAGE_TAG="${1#*=}";        shift;;
        --image-tag)             IMAGE_TAG="$2";             shift 2;;
        --deploy-dir=*)          DEPLOY_DIR="${1#*=}";       shift;;
        --deploy-dir)            DEPLOY_DIR="$2";            shift 2;;
        --no-browser)            NO_BROWSER=1;               shift;;
        --skip-build)            NO_BUILD=1;                 shift;;
        --rebuild)               REBUILD=1;                  shift;;
        --reseed)                AT_PRESEED=1; AT_PRESEED_FORCE=1; shift;;
        --no-seed)               AT_PRESEED=0;               shift;;
        --backend=*)             PY_BACKEND="${1#*=}";       shift;;
        --backend)               PY_BACKEND="$2";            shift 2;;
        --squad-size=*)          SQUAD_SIZE="${1#*=}";       shift;;
        --squad-size)            SQUAD_SIZE="$2";            shift 2;;
        --swarm-size=*)          SWARM_SIZE="${1#*=}";       shift;;
        --swarm-size)            SWARM_SIZE="$2";            shift 2;;
        --sensor-count=*)        SENSOR_COUNT="${1#*=}";     shift;;
        --sensor-count)          SENSOR_COUNT="$2";          shift 2;;
        --hacked-sensors=*)      HACKED_SENSORS="${1#*=}";   shift;;
        --hacked-sensors)        HACKED_SENSORS="$2";        shift 2;;
        --compromise-mode=*)     COMPROMISE_MODE="${1#*=}";  shift;;
        --compromise-mode)       COMPROMISE_MODE="$2";       shift 2;;
        --c-microdrones=*)       C_MICRODRONES="${1#*=}";    shift;;
        --c-microdrones)         C_MICRODRONES="all";        shift;;
        -v)                      LOG_LEVEL="info";           shift;;
        -vv)                     LOG_LEVEL="debug";          shift;;
        -vvv)                    LOG_LEVEL="verbose";        shift;;
        -h|--help)               usage 0;;
        -*) err "Unknown option: $1"; usage 1;;
        *)  POSITIONAL_ARGS+=("$1"); shift;;
    esac
done

# python/c take an optional positional NUM_NODES.
if (( ${#POSITIONAL_ARGS[@]} > 0 )); then
    NUM_NODES="${POSITIONAL_ARGS[0]}"
fi

# --- Per-variant defaults (after arg parse so user --options win) --------

case "$VARIANT" in
    python|c)
        # Tilt+docker-compose flow; the tiltfile owns gen_compose.py and
        # the compose YAML, so DEPLOY_DIR stays empty.
        TILT_LOG="${TILT_LOG:-/tmp/${VARIANT}-tilt.log}"
        ;;
    multi-agency)
        NAMESPACE="${NAMESPACE:-disaster-demo}"
        DEPLOY_DIR="${DEPLOY_DIR:-deploy/multi_agency}"
        TILT_LOG="${TILT_LOG:-/tmp/multi-agency-tilt.log}"
        ;;
    dod-mission)
        NAMESPACE="${NAMESPACE:-dod-demo}"
        DEPLOY_DIR="${DEPLOY_DIR:-examples/dod_mission/deploy}"
        TILT_LOG="${TILT_LOG:-/tmp/dod-mission-tilt.log}"
        ;;
    *)
        err "Unknown variant: $VARIANT"
        err "    Use one of: python, c, multi-agency, dod-mission"
        exit 1
        ;;
esac

K8S_DIR="$DEPLOY_DIR/kubernetes"
# multi-agency uses .yaml, dod-mission uses .yml; resolved per variant.
case "$VARIANT" in
    multi-agency) COMPOSE_FILE="$DEPLOY_DIR/docker-compose.yaml";;
    dod-mission)  COMPOSE_FILE="$DEPLOY_DIR/docker-compose.yml";;
    *)            COMPOSE_FILE="";;
esac

# --- Variant × mode validation -------------------------------------------
# bash 4+ assoc arrays not assumed (still want to run on stock macOS bash);
# encode as variant-suffixed plain vars.
ALLOWED_python="tilt teardown clean"
ALLOWED_c="tilt teardown clean"
ALLOWED_multi_agency="tilt compose k8s playback record teardown clean"
ALLOWED_dod_mission="tilt compose k8s teardown clean"

_variant_slug=${VARIANT//-/_}
_allowed_var="ALLOWED_${_variant_slug}"
_allowed="${!_allowed_var}"
if [[ ! " $_allowed " == *" $BACKEND_MODE "* ]]; then
    err "Backend mode '$BACKEND_MODE' is not valid for variant '$VARIANT'."
    err "    Allowed for $VARIANT: $_allowed"
    if [[ "$BACKEND_MODE" == "record" && "$VARIANT" == "dod-mission" ]]; then
        err "    To record a dod-mission live run, use: --record-to FILE"
    fi
    exit 1
fi

# Normalize the C-microdrone knob ("0"/"none"/"false" -> off) and gate it: the
# embedded C at_demo path exists in the dod-mission compose AND k8s generators
# (generate_compose.py / generate_k8s.py), the latter driving the tilt backend.
case "$C_MICRODRONES" in 0|none|false|off) C_MICRODRONES="";; esac
if [[ -n "$C_MICRODRONES" ]]; then
    if [[ "$VARIANT" != "dod-mission" ]]; then
        err "--c-microdrones is only supported with --variant=dod-mission."
        exit 1
    fi
    case "$BACKEND_MODE" in
        compose|tilt|k8s) : ;;  # all three generators emit C at_demo nodes
        *)
            err "--c-microdrones requires the --compose, --tilt, or --k8s"
            err "    backend (got --$BACKEND_MODE)."
            exit 1 ;;
    esac
fi

# dod-mission: --record-to FILE records the live run. The compose/k8s/tilt
# paths all generate via generate_compose/_k8s, which read AT_RECORD, so just
# export it; the coordinator then gets `--record` + a host-backed recording
# volume and flushes the canned-playback log on graceful shutdown.
if [[ -n "$RECORD_TO" ]]; then
    if [[ "$VARIANT" != "dod-mission" ]]; then
        err "--record-to is only supported for --variant=dod-mission"
        err "    (multi-agency records via its inspector-only --record FILE mode)"
        exit 1
    fi
    export AT_RECORD="$RECORD_TO"
    log "Recording this run -> coordinator writes $(basename "$RECORD_TO") on"
    log "    graceful shutdown (compose: ./recording/ beside the compose file;"
    log "    k8s: ${AT_RECORD_NODE_PATH:-/data/dod-mission-recording}/ on the node)."
fi

# --- Clean fast path ------------------------------------------------------

if [[ "$BACKEND_MODE" == "clean" ]]; then
    case "$VARIANT" in
        multi-agency)
            if [[ -d "$DEPLOY_DIR" ]]; then
                log "Removing $DEPLOY_DIR ..."
                rm -rf "$DEPLOY_DIR"
            fi
            ;;
        dod-mission)
            if [[ -f "$COMPOSE_FILE" ]]; then
                log "Bringing compose stack down..."
                docker compose -f "$COMPOSE_FILE" down 2>/dev/null || true
            fi
            log "Removing generated artifacts under $DEPLOY_DIR ..."
            rm -f "$COMPOSE_FILE"
            rm -rf "$K8S_DIR"
            rm -f "$here/examples/dod_mission/simulator/scenario.yaml" 2>/dev/null || true
            rm -rf "$here/examples/dod_mission/configs" 2>/dev/null || true
            ;;
        python|c)
            log "Nothing to clean — python/c variants are tilt-only and the"
            log "tiltfile owns the generated docker-compose.tilt.yaml."
            ;;
    esac
    log "Done."
    exit 0
fi

# --- HTTP / deployment readiness helpers ---------------------------------

# Block until a URL serves HTTP (not just until the port is bound).
# Usage: wait_for_http <url> [timeout_sec] [label] [tcp_fallback_port]
wait_for_http() {
    local url="$1"
    local timeout="${2:-180}"
    local label="${3:-service}"
    local tcp_port="${4:-}"
    local start now elapsed code last_progress=0
    start=$(date +%s)
    if ! command -v curl &>/dev/null; then
        if [[ -z "$tcp_port" ]]; then
            err "curl missing and no tcp_port supplied; cannot probe $url"
            return 1
        fi
        for _ in $(seq 1 $((timeout * 2))); do
            (echo >/dev/tcp/127.0.0.1/"$tcp_port") &>/dev/null && return 0
            sleep 0.5
        done
        return 1
    fi
    while :; do
        # curl's --write-out '%{http_code}' always emits exactly 3 chars
        # (000 on a failed connect / timeout). The previous `|| echo 000`
        # fallback concatenated with that on the failing path and printed
        # `http=000000` — drop the `||` and default an empty capture to
        # 000 instead.
        code=$(curl --silent --output /dev/null --max-time 2 \
                    --write-out '%{http_code}' "$url" 2>/dev/null)
        code=${code:-000}
        if [[ "$code" == "200" || "$code" == "302" ]]; then
            return 0
        fi
        now=$(date +%s); elapsed=$(( now - start ))
        (( elapsed >= timeout )) && return 1
        if (( elapsed - last_progress >= 10 )); then
            warn "  ... waiting for $label (${elapsed}s, http=$code)"
            last_progress=$elapsed
        fi
        sleep 1
    done
}

# Block until a k8s Deployment exists and reports Available. Used by the
# dod-mission tilt path to absorb tilt's image-build + manifest-apply
# latency before the HTTP probe starts polling (cold start can be
# minutes; the HTTP probe would otherwise time out before the
# coordinator pod is ContainerCreating, never mind Ready).
wait_for_deployment() {
    local ns="$1" deploy="$2"
    local timeout="${3:-1500}"
    local start last_progress=0 elapsed avail
    command -v kubectl &>/dev/null \
        || { warn "kubectl not available; skipping deployment readiness check"; return 0; }
    start=$(date +%s)
    # Phase 1: wait for the Deployment object to exist.
    while ! kubectl get deployment -n "$ns" "$deploy" >/dev/null 2>&1; do
        elapsed=$(( $(date +%s) - start ))
        if (( elapsed >= timeout )); then
            warn "$deploy not created in ${timeout}s (build likely stuck)"
            return 1
        fi
        if (( elapsed - last_progress >= 30 )); then
            warn "  ... tilt building images / applying manifests (${elapsed}s)"
            last_progress=$elapsed
        fi
        sleep 5
    done
    # Phase 2: deployment exists; wait for Available=True.
    last_progress=$(( $(date +%s) - start ))
    while :; do
        avail=$(kubectl get deployment -n "$ns" "$deploy" \
                -o jsonpath='{.status.conditions[?(@.type=="Available")].status}' \
                2>/dev/null || echo "")
        [[ "$avail" == "True" ]] && return 0
        elapsed=$(( $(date +%s) - start ))
        if (( elapsed >= timeout )); then
            warn "$deploy did not become Available in ${timeout}s"
            return 1
        fi
        if (( elapsed - last_progress >= 15 )); then
            warn "  ... waiting for $deploy pods to roll out (${elapsed}s)"
            last_progress=$elapsed
        fi
        sleep 3
    done
}

open_browser() {
    local url="$1"
    if (( NO_BROWSER == 1 )); then
        log "Dashboard available at: $url"
        return
    fi
    if command -v xdg-open &>/dev/null; then
        xdg-open "$url" &>/dev/null &
    elif command -v open &>/dev/null; then
        open "$url" &>/dev/null &
    else
        log "Dashboard available at: $url"
    fi
}

# Kill stale inspector processes / port-holders left over from a
# previous run that didn't shut down cleanly. Multi-agency runs the
# inspector host-side in playback/record modes; for compose/k8s/tilt
# the inspector is in-container and this is a no-op except for stuck
# host-side leftovers from a previous playback session.
cleanup_inspector_procs() {
    local pids
    if command -v lsof &>/dev/null; then
        pids=$(lsof -ti ":$INSPECTOR_PORT" 2>/dev/null || true)
        if [[ -n "$pids" ]]; then
            kill $pids 2>/dev/null || true
            sleep 0.5
            pids=$(lsof -ti ":$INSPECTOR_PORT" 2>/dev/null || true)
            [[ -n "$pids" ]] && kill -9 $pids 2>/dev/null || true
        fi
    elif command -v fuser &>/dev/null; then
        fuser -k "$INSPECTOR_PORT/tcp" 2>/dev/null || true
    fi
    pkill -f "examples\\.multi_agency" 2>/dev/null || true
}

# Force-reap the demo namespace's pods on Ctrl-C/teardown WITHOUT the heavy
# `minikube delete` that the --teardown path runs. `tilt down` deletes the
# Deployments, but pod termination is async and graceful: an AT node is slow
# to exit on SIGTERM (it tears down a multiprocessing pool of subprocesses),
# so the pod sits in Terminating with its whole python process tree still
# alive — visible host-side, "multiple per node". A grace-period-0 force
# delete SIGKILLs the pod sandboxes immediately so those trees die now,
# while minikube + the cached layer images are left intact for a fast next
# round. Best-effort and non-blocking (--wait=false) so the exit trap never
# hangs.
reap_namespace_fast() {
    [[ "$VARIANT" == "multi-agency" || "$VARIANT" == "dod-mission" ]] || return 0
    [[ -n "$NAMESPACE" ]] || return 0
    command -v kubectl &>/dev/null || return 0
    kubectl delete pods --all -n "$NAMESPACE" \
        --force --grace-period=0 --wait=false 2>/dev/null || true
    kubectl delete namespace "$NAMESPACE" \
        --ignore-not-found=true --wait=false 2>/dev/null || true
}

ensure_minikube_running() {
    if ! command -v minikube &>/dev/null; then
        err "minikube not installed; see https://minikube.sigs.k8s.io/docs/start/"
        err "(or rerun with --compose for the docker-compose backend)"
        exit 1
    fi
    if ! minikube status &>/dev/null; then
        log "Starting Minikube..."
        minikube start
    fi
}

# Switch to the cluster's docker daemon so subsequent `docker build`
# lands where pods can pull from. No-op on non-minikube contexts.
use_cluster_docker_env() {
    if command -v minikube &>/dev/null && minikube status &>/dev/null; then
        eval "$(minikube docker-env 2>/dev/null)" || true
    fi
}

# --- Build args (proxy + cert + git version) -----------------------------
# All variants need the same set; collected once so each ensure_*_images
# branch can splice it into its docker build invocations.

build_args=()
[[ -n "${http_proxy:-}" ]]   && build_args+=("--build-arg" "http_proxy=${http_proxy}")
[[ -n "${https_proxy:-}" ]]  && build_args+=("--build-arg" "https_proxy=${https_proxy}")
[[ -n "${no_proxy:-}" ]]     && build_args+=("--build-arg" "no_proxy=${no_proxy}")
proxy_ca="/usr/local/share/ca-certificates/proxy-ca.crt"
if [[ -r "$proxy_ca" ]]; then
    build_args+=("--build-arg" "CERT_CONTENT=$(cat "$proxy_ca")")
fi
git_version=$(git describe HEAD 2>/dev/null || echo unknown)
git_version="${git_version#v}"
build_args+=("--build-arg" "GIT_VERSION=$git_version")

# --- Stale-image schema-skew preflight -----------------------------------
# Catches the dod-mission "all forming…/peers.all=0" trap: tools/seed_dod_
# cohort.py runs from the host tree and serializes Identity with whatever
# fields the host identity.py declares (e.g. the ZTA zta_credential/zta_issuer/
# zta_credential_hash added in f6250c8). If the baked base image's
# Identity.__init__ predates those kwargs, every seeded peer TypeErrors at boot
# -> peers.all=0 -> reputations stuck "forming…". Returns 0 (stale) only when
# the image clearly exists AND is missing a kwarg the host source has; any
# uncertainty (no image, can't parse, can't introspect) returns 1 so the normal
# build path is never blocked.
base_image_identity_stale() {
    local base_ref="$1"
    docker image inspect "$base_ref" &>/dev/null || return 1

    local id_src="$here/src/autonomous-trust/autonomous_trust/core/_python/identity/identity.py"
    [[ -r "$id_src" ]] || return 1

    # Host kwarg set, via ast (no package import needed).
    local host_args
    host_args=$(python3 - "$id_src" <<'PY' 2>/dev/null
import ast, sys
mod = ast.parse(open(sys.argv[1]).read())
for cls in ast.walk(mod):
    if isinstance(cls, ast.ClassDef) and cls.name == "Identity":
        for fn in cls.body:
            if isinstance(fn, ast.FunctionDef) and fn.name == "__init__":
                a = fn.args
                names = [x.arg for x in a.args if x.arg != "self"] + [x.arg for x in a.kwonlyargs]
                print(" ".join(sorted(names)))
PY
)
    [[ -n "$host_args" ]] || return 1

    # Baked kwarg set, introspected from the image (entrypoint bypassed).
    local img_args
    img_args=$(docker run --rm --entrypoint python3 "$base_ref" -c \
        'import inspect; from autonomous_trust.core._python.identity.identity import Identity as I; p=inspect.signature(I.__init__).parameters; print(" ".join(sorted(x for x in p if x!="self")))' \
        2>/dev/null)
    [[ -n "$img_args" ]] || return 1

    local a
    for a in $host_args; do
        case " $img_args " in
            *" $a "*) ;;
            *) return 0 ;;   # image missing a host kwarg -> stale
        esac
    done
    return 1
}

# --- Image build chains (per variant) ------------------------------------
# Builds anything missing in the *active* docker daemon (host or
# cluster, depending on whether use_cluster_docker_env() was called
# first). Idempotent.

ensure_demo_images() {
    case "$VARIANT" in
        python|c)
            # Tilt's docker_build drives builds inside the python/c
            # tiltfile chain. Nothing to pre-build here.
            ;;
        multi-agency)
            local full_ref peer_ref inspector_ref
            full_ref="${REGISTRY}autonomous-trust${IMAGE_TAG}"
            peer_ref="${REGISTRY}autonomous-trust-disaster${IMAGE_TAG}"
            inspector_ref="${REGISTRY}autonomous-trust-inspector${IMAGE_TAG}"
            # --rebuild reaches the whole chain so source edits propagate;
            # without --no-cache, unchanged layers stay cached (see the
            # dod-mission branch below for the rationale).
            if (( REBUILD == 1 )) || ! docker image inspect "$full_ref" &>/dev/null; then
                log "Image $full_ref not found — building ..."
                docker build "${build_args[@]}" -t "$full_ref" \
                    -f "$here/src/autonomous-trust/Dockerfile-native" "$here"
            fi
            if (( REBUILD == 1 )) || ! docker image inspect "$peer_ref" &>/dev/null; then
                log "Image $peer_ref not found — building ..."
                docker build --build-arg "BASE_IMAGE=$full_ref" \
                    "${build_args[@]}" -t "$peer_ref" \
                    -f "$here/src/autonomous-trust-evaluation/Dockerfile" "$here"
            fi
            if (( REBUILD == 1 )) || ! docker image inspect "$inspector_ref" &>/dev/null; then
                log "Image $inspector_ref not found — building ..."
                docker build --build-arg "BASE_IMAGE=$full_ref" \
                    "${build_args[@]}" -t "$inspector_ref" \
                    -f "$here/src/autonomous-trust-inspector/Dockerfile" "$here"
            fi
            ;;
        dod-mission)
            local base_ref inspector_ref demo_ref peer_ref
            base_ref="${REGISTRY}autonomous-trust${IMAGE_TAG}"
            inspector_ref="${REGISTRY}autonomous-trust-inspector${IMAGE_TAG}"
            demo_ref="${REGISTRY}at-dod-mission-demo${IMAGE_TAG}"
            peer_ref="${REGISTRY}at-dod-mission-peer${IMAGE_TAG}"
            # Preflight: a base image whose baked Identity predates the host
            # source is the "all forming…/peers.all=0" trap (seeded peers
            # TypeError at boot). Detect it and force a --no-cache base rebuild
            # so the new identity.py is guaranteed to bake (a plain --rebuild
            # omits --no-cache and can be served a stale COPY layer). REBUILD=1
            # then cascades to the inspector/overlay images off the fresh base.
            local base_cache_flag=()
            if base_image_identity_stale "$base_ref"; then
                log "WARNING: base image '$base_ref' Identity schema is OLDER than host source."
                log "         Seeded peers would TypeError at boot -> reputations stuck 'forming…'."
                log "         Forcing a --no-cache rebuild of the image chain."
                REBUILD=1
                base_cache_flag=(--no-cache)
            fi
            # --rebuild must reach the base + inspector images, not just the
            # thin overlays below: the inspector image COPYs the frequently
            # edited Python source (core, inspector, evaluation, services,
            # simulator). Rebuilding only the dod overlay picks up new
            # examples/ code that imports new library symbols while the
            # inspector package underneath stays stale -> ImportError (e.g.
            # narration_script.py importing NarrationAnchor before the
            # inspector image carries it). These builds don't pass
            # --no-cache, so when the source is unchanged Docker hits the
            # layer cache and the forced rebuild is nearly free.
            if (( REBUILD == 1 )) || ! docker image inspect "$base_ref" &>/dev/null; then
                log "Building base image: $base_ref ..."
                docker build --network host "${base_cache_flag[@]}" "${build_args[@]}" -t "$base_ref" \
                    -f "$here/src/autonomous-trust/Dockerfile-native" "$here"
            fi
            if (( REBUILD == 1 )) || ! docker image inspect "$inspector_ref" &>/dev/null; then
                log "Building inspector image: $inspector_ref ..."
                docker build --network host --build-arg "BASE_IMAGE=$base_ref" \
                    "${build_args[@]}" -t "$inspector_ref" \
                    -f "$here/src/autonomous-trust-inspector/Dockerfile" "$here"
            fi
            # The two dod overlays are thin COPY layers; --rebuild forces
            # them to pick up edits under examples/dod_mission/ that
            # Docker's content-addressed cache might otherwise miss.
            if (( REBUILD == 1 )) || ! docker image inspect "$demo_ref" &>/dev/null; then
                log "Building DoD mission demo image (coord + sim): $demo_ref ..."
                docker build --network host --build-arg "BASE_IMAGE=$inspector_ref" \
                    "${build_args[@]}" -t "$demo_ref" \
                    -f "$here/examples/dod_mission/deploy/Dockerfile" "$here"
            fi
            if (( REBUILD == 1 )) || ! docker image inspect "$peer_ref" &>/dev/null; then
                log "Building DoD mission peer image (lean): $peer_ref ..."
                docker build --network host --build-arg "BASE_IMAGE=$base_ref" \
                    "${build_args[@]}" -t "$peer_ref" \
                    -f "$here/examples/dod_mission/deploy/Dockerfile-peer" "$here"
            fi
            # Embedded C at_demo image for --c-microdrones. Standalone build
            # (Dockerfile-c is FROM debian, no BASE_IMAGE); needs network for
            # apt, hence --network host. AT_C_IMAGE feeds generate_compose.py.
            if [[ -n "$C_MICRODRONES" ]]; then
                local c_ref="${REGISTRY}autonomous-trust-c${IMAGE_TAG}"
                export AT_C_IMAGE="$c_ref"
                if (( REBUILD == 1 )) || ! docker image inspect "$c_ref" &>/dev/null; then
                    log "Building embedded C at_demo image: $c_ref ..."
                    docker build --network host "${build_args[@]}" -t "$c_ref" \
                        -f "$here/src/autonomous-trust/Dockerfile-c" "$here"
                fi
            fi
            ;;
    esac
}

# --- Manifest generation (per variant) -----------------------------------
# Skipped in tilt mode — the variant's tiltfile owns regeneration via a
# local_resource so it re-fires when the scenario sources change.

generate_manifests() {
    case "$VARIANT" in
        python|c) ;;  # tiltfile drives gen_compose.py; nothing to do here.
        multi-agency)
            log "Generating manifests under $DEPLOY_DIR ..."
            python3 -m autonomous_trust.evaluation.scenarios.disaster_response_compose \
                --out "$DEPLOY_DIR" \
                --namespace "$NAMESPACE" \
                --registry "$REGISTRY" \
                --image autonomous-trust-disaster \
                --image-tag "$IMAGE_TAG" \
                --log-level "$LOG_LEVEL"
            ;;
        dod-mission)
            # Shared scenario T=0 epoch so every peer's DoDDataProcess
            # emits timestamps anchored to the same wall-clock origin.
            # Captured here (not in generate_compose.py) so --clean +
            # relaunch resets t0 rather than reusing a stale epoch.
            export AT_DEMO_T0_EPOCH=$(date +%s)
            local example_dir="$here/examples/dod_mission"
            if [[ "$BACKEND_MODE" == "compose" ]]; then
                # Per-peer configs: each peer container mounts its own
                # config dir; we materialize them on the host pre-up.
                log "Regenerating per-peer configs..."
                python3 - <<PY || warn "per-peer config generation failed (non-fatal; AT may regenerate at startup)"
import sys
sys.path.insert(0, '$here')
sys.path.insert(0, '$example_dir')
from autonomous_trust.evaluation.deployment import generate_peer_configs
from scenario import DoDMissionScenario
sc = DoDMissionScenario(
    squad_size=$SQUAD_SIZE, swarm_size=$SWARM_SIZE,
    sensor_count=$SENSOR_COUNT, hacked_sensors=$HACKED_SENSORS,
)
generate_peer_configs(sc, '$example_dir')
print(f'  configs written for {len(sc.peers)} peers')
PY
                log "Regenerating simulator scenario.yaml..."
                python3 "$example_dir/simulator/generate_scenario.py" \
                    "$example_dir/simulator/scenario.yaml" \
                    --squad-size "$SQUAD_SIZE" \
                    --swarm-size "$SWARM_SIZE" \
                    --sensor-count "$SENSOR_COUNT" \
                    --hacked-sensors "$HACKED_SENSORS" \
                    >/dev/null \
                    || warn "simulator scenario generation failed (non-fatal)"

                # --c-microdrones: render those microdrones as C at_demo nodes
                # (+ flight-stub sidecar), pinned to the locally-built C image.
                # Empty -> no C args, fully Python (back-compat default).
                compose_c_args=()
                if [[ -n "$C_MICRODRONES" ]]; then
                    compose_c_args+=(--c-microdrones "$C_MICRODRONES"
                                     --c-image "${AT_C_IMAGE:-${REGISTRY}autonomous-trust-c${IMAGE_TAG}}")
                fi

                log "Regenerating docker-compose.yml..."
                # Module form (mirrors generate_k8s below). PYTHONPATH
                # is exported at the top of this script, so `examples`
                # resolves.
                # Pin the image to the locally-built tag (e.g. :dev). Without
                # this the compose defaults to the untagged DEMO_IMAGE, which
                # Docker reads as :latest and then tries to PULL — failing with
                # "pull access denied" since only the :dev tag exists locally.
                # Mirrors the --image-tag the k8s generator already gets below.
                python3 -m examples.dod_mission.deploy.generate_compose \
                    "$COMPOSE_FILE" \
                    --image "${REGISTRY}at-dod-mission-demo${IMAGE_TAG}" \
                    --squad-size "$SQUAD_SIZE" \
                    --swarm-size "$SWARM_SIZE" \
                    --sensor-count "$SENSOR_COUNT" \
                    --hacked-sensors "$HACKED_SENSORS" \
                    "${compose_c_args[@]+"${compose_c_args[@]}"}" \
                    || { err "compose generation failed"; exit 1; }

                if [[ "${AT_PRESEED:-1}" == "1" ]]; then
                    # Seed the per-peer persistent dirs that compose
                    # bind-mounts into each container at start. squad-*,
                    # microdrone-*, jet-* get a mutually-recognised
                    # identity + rep=0.7 starting state; everyone else
                    # gets an empty dir and goes through normal
                    # bootstrap. AT_PRESEED_FORCE=1 regenerates fresh
                    # identities (default is to preserve existing keys
                    # so warm restarts stay consistent).
                    log "Seeding persistent-cohort dirs under .demo-state/dod-mission/ ..."
                    seed_force=""
                    [[ "${AT_PRESEED_FORCE:-0}" == "1" ]] && seed_force="--force"
                    # On --reseed, clear root-owned container state first (see
                    # reseed_wipe_state) so the fresh seed isn't shadowed by it.
                    [[ -n "$seed_force" ]] && reseed_wipe_state "$here/.demo-state/dod-mission"
                    # Seed C-format identities for the C microdrones so the SPEC
                    # matches generate_compose.py exactly (a peer running the C
                    # node must be seeded C, and vice-versa). No spaces in SPEC.
                    seed_c_arg=""
                    [[ -n "$C_MICRODRONES" ]] && seed_c_arg="--c-microdrones $C_MICRODRONES"
                    python3 -m tools.seed_dod_cohort \
                        --out .demo-state/dod-mission \
                        --squad-size "$SQUAD_SIZE" \
                        --swarm-size "$SWARM_SIZE" \
                        --sensor-count "$SENSOR_COUNT" \
                        --hacked-sensors "$HACKED_SENSORS" \
                        $seed_force $seed_c_arg \
                        || { err "cohort seed failed"; exit 1; }
                    if [[ "${AT_ZTA_PROVISION:-1}" == "1" ]]; then
                        log "Provisioning ZTA mission CA + per-peer credentials ..."
                        AT_SQUAD_SIZE="$SQUAD_SIZE" AT_SWARM_SIZE="$SWARM_SIZE" \
                        AT_SENSOR_COUNT="$SENSOR_COUNT" AT_HACKED_SENSORS="$HACKED_SENSORS" \
                        python3 -m tools.provision_zta_certs \
                            --out-root .demo-state/dod-mission \
                            || warn "ZTA provisioning failed (non-fatal; peers cold-bootstrap without ZTA)"
                    fi
                else
                    log "AT_PRESEED=0: skipping cohort seed (peers will cold-bootstrap)"
                fi
            elif [[ "$BACKEND_MODE" == "k8s" ]]; then
                # k8s manifest generation. tilt mode regenerates via
                # the tiltfile's own local_resource; here we drive the
                # generator from the script side so a non-tilt
                # `--k8s` launch (kubectl apply -f ...) sees fresh
                # manifests too. Mirrors the multi-agency k8s branch
                # above. AUTONOMOUS_TRUST_EXE/peer image refs default
                # inside generate_k8s.py to at-dod-mission-{demo,peer}
                # — pass --registry/--image-tag to override at scale.
                log "Regenerating simulator scenario.yaml..."
                python3 "$example_dir/simulator/generate_scenario.py" \
                    "$example_dir/simulator/scenario.yaml" \
                    --squad-size "$SQUAD_SIZE" \
                    --swarm-size "$SWARM_SIZE" \
                    --sensor-count "$SENSOR_COUNT" \
                    --hacked-sensors "$HACKED_SENSORS" \
                    >/dev/null \
                    || warn "simulator scenario generation failed (non-fatal)"
                seed_root_arg=""
                if [[ "${AT_PRESEED:-1}" == "1" ]]; then
                    log "Seeding persistent-cohort dirs under .demo-state/dod-mission/ ..."
                    seed_force=""
                    [[ "${AT_PRESEED_FORCE:-0}" == "1" ]] && seed_force="--force"
                    # On --reseed, clear root-owned container state first (see
                    # reseed_wipe_state) so the fresh seed isn't shadowed by it.
                    [[ -n "$seed_force" ]] && reseed_wipe_state "$here/.demo-state/dod-mission"
                    # Seed C-format identities for the C microdrones so the SPEC
                    # matches generate_k8s.py exactly (C Pod <-> C identity).
                    seed_c_arg=""
                    [[ -n "$C_MICRODRONES" ]] && seed_c_arg="--c-microdrones $C_MICRODRONES"
                    python3 -m tools.seed_dod_cohort \
                        --out .demo-state/dod-mission \
                        --squad-size "$SQUAD_SIZE" \
                        --swarm-size "$SWARM_SIZE" \
                        --sensor-count "$SENSOR_COUNT" \
                        --hacked-sensors "$HACKED_SENSORS" \
                        $seed_force $seed_c_arg \
                        || { err "cohort seed failed"; exit 1; }
                    if [[ "${AT_ZTA_PROVISION:-1}" == "1" ]]; then
                        log "Provisioning ZTA mission CA + per-peer credentials ..."
                        AT_SQUAD_SIZE="$SQUAD_SIZE" AT_SWARM_SIZE="$SWARM_SIZE" \
                        AT_SENSOR_COUNT="$SENSOR_COUNT" AT_HACKED_SENSORS="$HACKED_SENSORS" \
                        python3 -m tools.provision_zta_certs \
                            --out-root .demo-state/dod-mission \
                            || warn "ZTA provisioning failed (non-fatal; peers cold-bootstrap without ZTA)"
                    fi
                    seed_root_arg="--seed-root .demo-state/dod-mission"
                else
                    log "AT_PRESEED=0: skipping cohort seed (peers will cold-bootstrap)"
                fi
                k8s_c_arg=""
                [[ -n "$C_MICRODRONES" ]] && k8s_c_arg="--c-microdrones $C_MICRODRONES"
                log "Generating kubernetes manifests under $K8S_DIR ..."
                python3 -m examples.dod_mission.deploy.generate_k8s \
                    --out "$K8S_DIR" \
                    --namespace "$NAMESPACE" \
                    --registry "$REGISTRY" \
                    --image-tag "$IMAGE_TAG" \
                    --log-level "$LOG_LEVEL" \
                    --compromise-mode "$COMPROMISE_MODE" \
                    --squad-size "$SQUAD_SIZE" \
                    --swarm-size "$SWARM_SIZE" \
                    --sensor-count "$SENSOR_COUNT" \
                    --hacked-sensors "$HACKED_SENSORS" \
                    $seed_root_arg $k8s_c_arg \
                    || { err "k8s manifest generation failed"; exit 1; }
            fi
            ;;
    esac
}

# --- Variant-specific arg lists for tilt up/down --------------------------
# Each `tilt up` / `tilt down` goes through the top-level Tiltfile which
# routes by --variant. Compose extra args (namespace, log-level, scenario
# knobs) flow via env vars exported in the variant block.

# tilt_args runs in a $(...) / <(...) subshell at every call site;
# exports inside it would die with the subshell, so the dod-mission
# scaling knobs are exported separately by prepare_tilt_env (which
# runs in the parent shell) before any tilt invocation.
prepare_tilt_env() {
    case "$VARIANT" in
        dod-mission)
            export _TILT_SWARM_SIZE="$SWARM_SIZE"
            export _TILT_SENSOR_COUNT="$SENSOR_COUNT"
            export _TILT_HACKED_SENSORS="$HACKED_SENSORS"
            export _TILT_COMPROMISE_MODE="$COMPROMISE_MODE"
            # Embedded-C microdrones: the tiltfile reads this, builds the
            # autonomous-trust-c image, and threads the SPEC to generate_k8s +
            # seed_dod_cohort. Empty => all-Python (back-compat).
            export _TILT_C_MICRODRONES="$C_MICRODRONES"
            ;;
    esac
}

tilt_args() {
    local args=("--variant=$VARIANT" "--log-level=$LOG_LEVEL")
    case "$VARIANT" in
        python|c)
            args+=("--num-nodes=$NUM_NODES")
            [[ "$VARIANT" == "python" ]] && args+=("--backend=$PY_BACKEND")
            ;;
        multi-agency|dod-mission)
            args+=("--namespace=$NAMESPACE")
            ;;
    esac
    printf '%s\n' "${args[@]}"
}

# --- Conda env gate -------------------------------------------------------
# Every backend below shells out to the host `python3` (manifest generation,
# cohort seeding, ZTA provisioning, the multi-agency playback/record nodes),
# all of which expect the project's `autonomous_trust` conda env to be active
# so the interpreter carries the AT deps. Matches the gating convention in
# scripts/build-py.sh and scripts/scale-test-dod-mission.sh. --help and --clean
# have already short-circuited above; --teardown only drives tilt/kubectl/
# minikube and needs no AT python, so it is exempt.
CONDA_ENV_NAME="${CONDA_ENV_NAME:-autonomous_trust}"
if [[ "$BACKEND_MODE" != "teardown" && "${CONDA_DEFAULT_ENV:-}" != "$CONDA_ENV_NAME" ]]; then
    err "conda environment '$CONDA_ENV_NAME' is not active."
    err "    Run: conda activate $CONDA_ENV_NAME"
    exit 1
fi

# --- Tool preflight -------------------------------------------------------

command -v docker  &>/dev/null || { err "docker not found"; exit 1; }
command -v python3 &>/dev/null || { err "python3 not found"; exit 1; }
if [[ "$BACKEND_MODE" == "tilt" ]]; then
    command -v tilt    &>/dev/null \
        || { err "tilt not found; install from https://docs.tilt.dev/"; exit 1; }
    if [[ "$VARIANT" == "multi-agency" || "$VARIANT" == "dod-mission" ]]; then
        command -v kubectl &>/dev/null \
            || { err "kubectl not found (tilt needs a working kube context)"; exit 1; }
    fi
fi

# --- Teardown fast path ---------------------------------------------------

if [[ "$BACKEND_MODE" == "teardown" ]]; then
    prepare_tilt_env
    case "$VARIANT" in
        python|c)
            if command -v tilt &>/dev/null; then
                log "tilt down (variant=$VARIANT) ..."
                mapfile -t _ta < <(tilt_args)
                tilt down -- "${_ta[@]}" 2>>"$TILT_LOG" || true
            fi
            ;;
        multi-agency|dod-mission)
            if command -v tilt &>/dev/null; then
                log "tilt down (variant=$VARIANT, ns=$NAMESPACE) ..."
                mapfile -t _ta < <(tilt_args)
                tilt down -- "${_ta[@]}" 2>>"$TILT_LOG" || true
            fi
            if command -v kubectl &>/dev/null; then
                # Belt-and-suspenders: drop the namespace in case tilt down
                # left a terminating pod or two behind.
                kubectl delete namespace "$NAMESPACE" --ignore-not-found=true \
                    --timeout=30s 2>/dev/null || true
            fi
            if command -v minikube &>/dev/null; then
                # Full cluster teardown: removes the minikube VM/profile
                # (and with it every namespace + cached image), so the
                # next launch starts from a clean cluster. Heavier than
                # the namespace delete above, which still runs first as a
                # fast path in case minikube is absent.
                log "minikube delete ..."
                minikube delete 2>/dev/null || true
            fi
            [[ "$VARIANT" == "dod-mission" ]] && rm -rf "$K8S_DIR"
            ;;
    esac
    cleanup_inspector_procs
    log "Teardown complete."
    exit 0
fi

# --- Playback / record fast paths (multi-agency only) --------------------

if [[ "$BACKEND_MODE" == "playback" ]]; then
    [[ -f "$PLAYBACK_FILE" ]] || { err "Playback file not found: $PLAYBACK_FILE"; exit 1; }
    log "Inspector-only playback mode."
    export AT_DEMO_PLAYBACK_FILE="$PLAYBACK_FILE"
    exec python3 -m examples.multi_agency \
        --playback "$PLAYBACK_FILE" \
        --port "$INSPECTOR_PORT"
fi

if [[ "$BACKEND_MODE" == "record" ]]; then
    [[ -n "$RECORD_FILE" ]] || { err "Missing --record FILE argument"; exit 1; }
    mkdir -p "$(dirname -- "$RECORD_FILE")"
    log "Inspector-only recording mode."
    log "    Output: $RECORD_FILE (written on Ctrl-C)"
    exec python3 -m examples.multi_agency \
        --record "$RECORD_FILE" \
        --port "$INSPECTOR_PORT" \
        --log-level "$LOG_LEVEL"
fi

# --- Manifest generation (compose/k8s only) ------------------------------

if [[ "$BACKEND_MODE" == "compose" || "$BACKEND_MODE" == "k8s" ]]; then
    generate_manifests
fi

# --- Trap: always reap host-side leftovers on exit ------------------------

trap 'cleanup_inspector_procs' EXIT

# --- Dispatch -------------------------------------------------------------

case "$BACKEND_MODE" in

    tilt)
        if [[ "$VARIANT" == "multi-agency" || "$VARIANT" == "dod-mission" ]]; then
            ensure_minikube_running
            if (( NO_BUILD == 0 )); then
                # Switch to the cluster's daemon so Tilt's docker_build lands
                # where the pods pull from.
                use_cluster_docker_env
                # dod-mission: its tiltfile now wires BASE_IMAGE per image, so
                # Tilt owns the whole FROM chain (base -> inspector -> demo/peer)
                # and rebuilds on content change. Pre-seeding here just built
                # every image a second time (Tilt rebuilds them all on `up`), so
                # it's skipped — matching the python/c variants which never
                # pre-build. multi-agency still pre-seeds (:dev tags) because its
                # tiltfile doesn't pass BASE_IMAGE yet.
                #
                # NOTE (trade-off): this drops the old preflight's two side
                # effects for dod-mission — (1) forcing a fresh build after a
                # `docker rmi` (Tilt's content-hash cache doesn't notice a
                # daemon-side rmi), and (2) the base_image_identity_stale
                # guard. Tilt's content-hash caching rebuilds when the copied
                # source changes, so a normal edit is covered; a manual `rmi`
                # mid-session may need `tilt trigger` / `--rebuild`.
                if [[ "$VARIANT" == "multi-agency" ]]; then
                    log "Preflight image check ..."
                    ensure_demo_images
                fi
            fi
        fi

        log "Starting Tilt (variant=$VARIANT) ..."
        log "    Logs: tail -f $TILT_LOG"
        log "    UI:   http://localhost:10350"
        [[ "$VARIANT" == "multi-agency" || "$VARIANT" == "dod-mission" ]] && \
            log "    Tilt down: $0 --variant=$VARIANT --teardown"

        prepare_tilt_env
        mapfile -t _ta < <(tilt_args)
        # tilt up in background so wait_for_http can race readiness against
        # tilt's image-build chain.  Non-TTY stdout keeps tilt in streaming-
        # log mode rather than its interactive TUI.
        tilt up -- "${_ta[@]}" &>"$TILT_LOG" &
        TILT_PID=$!

        # Split traps so Ctrl-C interrupts wait_for_http's `sleep 1` loop.
        # EXIT does the heavy lift (tilt down + cluster cleanup); INT/TERM
        # only call `exit` so the signal propagates immediately.
        trap '_ta_down=$(tilt_args); \
              kill $TILT_PID 2>/dev/null || true; \
              wait $TILT_PID 2>/dev/null || true; \
              tilt down -- $_ta_down &>>"$TILT_LOG" || true; \
              reap_namespace_fast; \
              cleanup_inspector_procs' EXIT
        trap 'echo; log "Stopping Tilt..."; exit 130' INT
        trap 'echo; log "Stopping Tilt..."; exit 143' TERM

        # Open Tilt UI as soon as it's serving so the user can watch image
        # builds and pod rollout while inspector / coordinator boots.
        tilt_ui_url="http://localhost:10350/"
        log "Waiting for Tilt UI at $tilt_ui_url ..."
        if wait_for_http "$tilt_ui_url" 30 "tilt UI" 10350; then
            open_browser "$tilt_ui_url"
        else
            warn "Tilt UI not reachable within 30s; continuing."
        fi

        # dod-mission's first cold tilt run is dominated by 4 image builds
        # + k8s rollout; gate the HTTP probe on the coordinator Deployment
        # being Available so it doesn't time out before the pod is
        # ContainerCreating.
        if [[ "$VARIANT" == "dod-mission" ]]; then
            log "Waiting for tilt to build images + roll out coordinator ..."
            log "    (this can take 5-15min on a cold cluster; tail -f $TILT_LOG)"
            wait_for_deployment "$NAMESPACE" "dod-coordinator" 1500 \
                || warn "Coordinator deployment did not become Available."
        fi

        # Inspector readiness probe — only the k8s scenario variants ship
        # a separate Dash dashboard. python/c variants surface everything
        # through the Tilt UI (already opened above), so there's no
        # second port to probe.
        if [[ "$VARIANT" == "multi-agency" || "$VARIANT" == "dod-mission" ]]; then
            local_inspector_url="http://localhost:$INSPECTOR_PORT/"
            probe_timeout=600
            log "Waiting for inspector at $local_inspector_url ..."
            if wait_for_http "$local_inspector_url" "$probe_timeout" "inspector" "$INSPECTOR_PORT"; then
                open_browser "$local_inspector_url"
            else
                warn "Inspector did not respond within ${probe_timeout}s; check $TILT_LOG"
                warn "    Tilt UI:  http://localhost:10350"
                warn "    Pods:     kubectl -n $NAMESPACE get pods"
            fi
        fi

        echo ""
        log "--- Running. Ctrl-C to tear down ---"
        wait $TILT_PID
        ;;

    compose)
        ensure_demo_images
        cleanup_inspector_procs

        # Multi-agency probes shared volume: compose generator emits a
        # relative bind `./at-probes:/var/at-probes` on every service;
        # docker resolves it against $DEPLOY_DIR. Create + start fresh
        # before `up`.
        if [[ "$VARIANT" == "multi-agency" && -n "${AT_PROBES:-}" ]]; then
            probe_host_dir="${AT_PROBES_HOST_DIR:-./at-probes}"
            probe_abs="$DEPLOY_DIR/${probe_host_dir#./}"
            mkdir -p "$probe_abs"
            find "$probe_abs" -name 'probes_*.jsonl' -type f -delete 2>/dev/null || true
            log "Probes ON: writing to $probe_abs"
            log "    after run:  scripts/probe-tail.py --dir $probe_abs"
        fi

        # Compromise mode flows into peer containers via env (dod-mission).
        [[ "$VARIANT" == "dod-mission" ]] && export AT_COMPROMISE_MODE="$COMPROMISE_MODE"

        # Throttle docker compose's daemon-call concurrency (portable
        # back to compose v2.0). Without this, ~100 simultaneous
        # container creates have been observed to stall the daemon's
        # filesystem layer — observed first on dod-mission, ported here
        # so multi-agency at scale doesn't hit the same wall.
        export COMPOSE_PARALLEL_LIMIT="${COMPOSE_PARALLEL_LIMIT:-10}"

        log "Bringing stack up (docker compose, COMPOSE_PARALLEL_LIMIT=$COMPOSE_PARALLEL_LIMIT) ..."
        case "$VARIANT" in
            multi-agency)
                pushd "$DEPLOY_DIR" >/dev/null
                docker compose up -d
                popd >/dev/null
                ;;
            dod-mission)
                log "  Compromise mode:   $COMPROMISE_MODE"
                log "  Peers:             $((SQUAD_SIZE + SWARM_SIZE + SENSOR_COUNT + 5)) total"
                log "  Squad / Swarm:     $SQUAD_SIZE soldiers, $SWARM_SIZE microdrones"
                log "  Sensors / Hacked:  $SENSOR_COUNT leave-behind ($HACKED_SENSORS hacked)"
                docker compose -f "$COMPOSE_FILE" up -d
                ;;
        esac

        log "Waiting for inspector at http://localhost:$INSPECTOR_PORT/ ..."
        if wait_for_http "http://localhost:$INSPECTOR_PORT/" 180 "inspector" "$INSPECTOR_PORT"; then
            open_browser "http://localhost:$INSPECTOR_PORT/"
        else
            warn "Inspector did not respond within 180s; opening anyway."
            case "$VARIANT" in
                multi-agency) warn "  docker logs multi-agency-inspector";;
                dod-mission)  warn "  docker compose -f $COMPOSE_FILE logs -f coordinator";;
            esac
            open_browser "http://localhost:$INSPECTOR_PORT/"
        fi

        echo ""
        log "--- Running. Ctrl-C to stop ---"
        case "$VARIANT" in
            multi-agency)
                log "Inspector logs: docker logs -f multi-agency-inspector"
                trap '(cd "$DEPLOY_DIR" && docker compose down) || true; \
                      cleanup_inspector_procs' EXIT
                ;;
            dod-mission)
                log "Container logs: docker compose -f $COMPOSE_FILE logs -f"
                log "Stop / cleanup: $0 --variant=dod-mission --clean"
                trap 'docker compose -f "$COMPOSE_FILE" down 2>/dev/null || true; \
                      cleanup_inspector_procs' EXIT
                ;;
        esac
        trap 'echo; log "Stopping..."; exit 130' INT
        trap 'echo; log "Stopping..."; exit 143' TERM

        # Hold the foreground until the stack stops on its own (or Ctrl-C).
        case "$VARIANT" in
            multi-agency)
                while (cd "$DEPLOY_DIR" && docker compose ps --services \
                        --filter status=running | grep -q .); do
                    sleep 5
                done
                ;;
            dod-mission)
                while docker compose -f "$COMPOSE_FILE" ps --services \
                        --filter status=running 2>/dev/null | grep -q .; do
                    sleep 5
                done
                ;;
        esac
        ;;

    k8s)
        # multi-agency + dod-mission share most of the k8s flow (apply
        # manifests, wait, resolve dashboard URL, watch the namespace).
        # The only variant-specific bits are the inspector Deployment
        # name and the NodePort service name; both are captured here.
        case "$VARIANT" in
            multi-agency)
                inspector_deploy="multi-agency-inspector"
                inspector_svc="multi-agency-inspector"
                ;;
            dod-mission)
                inspector_deploy="dod-coordinator"
                inspector_svc="dod-coordinator"
                ;;
        esac

        ensure_minikube_running
        log "Applying manifests to namespace $NAMESPACE ..."
        kubectl apply -f "$K8S_DIR/namespace.yaml"
        kubectl apply -f "$K8S_DIR/scenario-config.yaml"
        for f in "$K8S_DIR"/*.yaml; do
            case "$(basename "$f")" in
                namespace.yaml|scenario-config.yaml) ;;
                *) kubectl apply -f "$f";;
            esac
        done

        use_cluster_docker_env
        ensure_demo_images

        log "Waiting for pods in $NAMESPACE ..."
        kubectl wait --for=condition=Ready pods --all --namespace "$NAMESPACE" \
            --timeout=180s || true

        log "Resolving inspector service URL ..."
        inspector_url=$(minikube service "$inspector_svc" \
            -n "$NAMESPACE" --url 2>/dev/null | head -1)
        if [[ -z "$inspector_url" ]]; then
            warn "minikube service URL unavailable; falling back to NodePort lookup"
            node_port=$(kubectl get svc "$inspector_svc" \
                -n "$NAMESPACE" -o jsonpath='{.spec.ports[0].nodePort}' 2>/dev/null)
            node_ip=$(minikube ip 2>/dev/null)
            if [[ -n "$node_ip" && -n "$node_port" ]]; then
                inspector_url="http://$node_ip:$node_port"
            else
                err "Could not determine inspector URL; check kubectl get svc -n $NAMESPACE"
                exit 1
            fi
        fi

        log "Waiting for inspector at $inspector_url ..."
        if wait_for_http "$inspector_url/" 180 "inspector"; then
            open_browser "$inspector_url/"
        else
            warn "Inspector did not respond within 180s; opening anyway."
            warn "  kubectl logs -n $NAMESPACE deployment/$inspector_deploy"
            open_browser "$inspector_url/"
        fi

        echo ""
        log "--- Running. Ctrl-C to tear down ---"
        log "Inspector logs: kubectl logs -n $NAMESPACE -f deployment/$inspector_deploy"
        trap 'kubectl delete namespace "$NAMESPACE" --ignore-not-found || true; \
              cleanup_inspector_procs' EXIT
        trap 'echo; log "Stopping..."; exit 130' INT
        trap 'echo; log "Stopping..."; exit 143' TERM
        while kubectl get deployment "$inspector_deploy" \
                -n "$NAMESPACE" &>/dev/null; do
            sleep 5
        done
        ;;

    *)
        err "Unhandled backend mode: $BACKEND_MODE"
        exit 2
        ;;
esac
