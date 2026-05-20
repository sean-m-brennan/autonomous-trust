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
# One-command launcher for the civilian disaster-response demo.
#
# What it does:
#   1. Regenerates docker-compose.yaml + kubernetes/ manifests from the
#      DisasterResponseScenario definition (so the deployment always
#      matches the scenario peers).
#   2. Picks a backend:
#        --compose (default on Linux laptops) -> docker compose up
#        --k8s                                 -> minikube + kubectl apply
#        --playback FILE                       -> inspector only,
#                                                 replay canned JSON
#   3. Starts the inspector and opens a browser to the dashboard.
#
# The generated outputs live under ./deploy/civilian/ by default so the
# tracked tree isn't polluted; clean with:
#     scripts/run-demo-civilian.sh --clean
#
# Examples:
#     scripts/run-demo-civilian.sh                      # compose, default port
#     scripts/run-demo-civilian.sh --k8s --namespace disaster-demo
#     scripts/run-demo-civilian.sh --playback recording.json

set -euo pipefail

# --- Paths ---------------------------------------------------------------

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$here"

# Put the namespace-package sources on PYTHONPATH so host-side python can
# import autonomous_trust.{evaluation,inspector,...} without a pip install.
AT_SRC_PATHS="$here/src/autonomous-trust:$here/src/autonomous-trust-evaluation:$here/src/autonomous-trust-inspector:$here/src/autonomous-trust-services:$here/src/autonomous-trust-simulator"
export PYTHONPATH="${AT_SRC_PATHS}${PYTHONPATH:+:$PYTHONPATH}"

# Force native backend on the host so it matches the peer containers.
# Overridable for debug; fallback to _python still applies per-module
# via the core redirector.
export AUTONOMOUS_TRUST_BACKEND="${AUTONOMOUS_TRUST_BACKEND:-native}"

DEPLOY_DIR="${DEPLOY_DIR:-deploy/civilian}"
NAMESPACE="${NAMESPACE:-disaster-demo}"
INSPECTOR_PORT="${INSPECTOR_PORT:-8050}"
REGISTRY="${REGISTRY:-}"
IMAGE_TAG="${IMAGE_TAG:-:dev}"
IMAGE_NAME="${IMAGE_NAME:-autonomous-trust}"
LOG_LEVEL="${LOG_LEVEL:-info}"
BACKEND_MODE="compose"
PLAYBACK_FILE=""

# --- Argument parsing ----------------------------------------------------

usage() {
    cat <<EOF
Usage: $0 [options]

Deployment modes (pick one):
  --compose                  docker compose (default)
  --k8s                      Minikube + kubectl
  --playback <FILE>          Inspector only; replay events from FILE.json

Options:
  --namespace NS             K8s namespace (default: $NAMESPACE)
  --deploy-dir DIR           Output dir for generated files
                             (default: $DEPLOY_DIR)
  --port PORT                Inspector port (default: $INSPECTOR_PORT)
  --registry PREFIX          Image registry (include trailing /)
  --image-tag TAG            Image tag, include leading : (default: $IMAGE_TAG)
  --log-level LEVEL          info | debug | warning (default: info)
  --no-browser               Don't auto-open the browser
  --clean                    Remove generated deploy dir and exit
  -h, --help                 Show this message

Environment overrides: DEPLOY_DIR, NAMESPACE, INSPECTOR_PORT,
REGISTRY, IMAGE_TAG, LOG_LEVEL
EOF
    exit "${1:-0}"
}

NO_BROWSER=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --compose)      BACKEND_MODE="compose"; shift;;
        --k8s)          BACKEND_MODE="k8s";     shift;;
        --playback)     BACKEND_MODE="playback"; PLAYBACK_FILE="$2"; shift 2;;
        --namespace)    NAMESPACE="$2";          shift 2;;
        --deploy-dir)   DEPLOY_DIR="$2";         shift 2;;
        --port)         INSPECTOR_PORT="$2";     shift 2;;
        --registry)     REGISTRY="$2";           shift 2;;
        --image-tag)    IMAGE_TAG="$2";          shift 2;;
        --log-level)    LOG_LEVEL="$2";          shift 2;;
        --no-browser)   NO_BROWSER=1;            shift;;
        --clean)
            if [[ -d "$DEPLOY_DIR" ]]; then
                echo "Removing $DEPLOY_DIR"
                rm -rf "$DEPLOY_DIR"
            fi
            exit 0
            ;;
        -h|--help)      usage 0;;
        *) echo "Unknown option: $1" >&2; usage 1;;
    esac
done

# --- Playback-only fast path --------------------------------------------

if [[ "$BACKEND_MODE" == "playback" ]]; then
    if [[ ! -f "$PLAYBACK_FILE" ]]; then
        echo "Playback file not found: $PLAYBACK_FILE" >&2
        exit 1
    fi
    echo "=== Inspector-only playback mode ==="
    export AT_DEMO_PLAYBACK_FILE="$PLAYBACK_FILE"
    exec python3 -m autonomous_trust.inspector \
        --demo-civilian \
        --playback "$PLAYBACK_FILE" \
        --port "$INSPECTOR_PORT"
fi

# --- Generate manifests --------------------------------------------------

echo "=== Generating manifests under $DEPLOY_DIR ==="
python3 -m autonomous_trust.evaluation.scenarios.disaster_response_compose \
    --out "$DEPLOY_DIR" \
    --namespace "$NAMESPACE" \
    --registry "$REGISTRY" \
    --image-tag "$IMAGE_TAG" \
    --log-level "$LOG_LEVEL"

# --- Dispatch on mode ----------------------------------------------------

open_browser() {
    local url="$1"
    if (( NO_BROWSER == 1 )); then
        echo "Dashboard available at: $url"
        return
    fi
    if command -v xdg-open &>/dev/null; then
        xdg-open "$url" &>/dev/null &
    elif command -v open &>/dev/null; then
        open "$url" &>/dev/null &
    else
        echo "Dashboard available at: $url"
    fi
}

# Kill any stale inspector processes or port-holders left over from a
# previous run that didn't shut down cleanly. Called preflight and on
# exit. Safe to run with nothing to clean.
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
    # Also sweep any AT worker processes that may have outlived their
    # parent. Scoped to this repo path so we don't touch unrelated envs.
    pkill -f "autonomous_trust\\.inspector" 2>/dev/null || true
}

case "$BACKEND_MODE" in
    compose)
        command -v docker &>/dev/null \
            || { echo "docker not found"; exit 1; }

        # Ensure the peer image exists; build with Dockerfile-native
        # (matches AUTONOMOUS_TRUST_BACKEND=native in the generated
        # compose env and tilt/python.tiltfile's native path).
        full_ref="${REGISTRY}${IMAGE_NAME}${IMAGE_TAG}"
        if ! docker image inspect "$full_ref" &>/dev/null; then
            echo "=== Image $full_ref not found locally — building ==="
            docker build \
                -t "$full_ref" \
                -f "$here/src/autonomous-trust/Dockerfile-native" \
                "$here"
        fi

        # Ensure the civilian-inspector image exists. Extends the peer
        # image with Dash deps + sibling AT subpackages.
        inspector_ref="${REGISTRY}autonomous-trust-inspector${IMAGE_TAG}"
        if ! docker image inspect "$inspector_ref" &>/dev/null; then
            echo "=== Image $inspector_ref not found locally — building ==="
            docker build \
                --build-arg "BASE_IMAGE=$full_ref" \
                -t "$inspector_ref" \
                -f "$here/src/autonomous-trust-inspector/Dockerfile-civilian" \
                "$here"
        fi

        # Preflight: nothing to clean process-wise now (inspector runs
        # inside the compose stack), but free the host port in case an
        # older host-run inspector is still bound.
        cleanup_inspector_procs

        # Probes shared volume: compose generator emits a relative bind
        # `./at-probes:/var/at-probes` on every service, which docker
        # resolves against $DEPLOY_DIR. Create it (and start fresh)
        # before `up` so peers don't write to a stale aggregation.
        if [[ -n "${AT_PROBES:-}" ]]; then
            probe_host_dir="${AT_PROBES_HOST_DIR:-./at-probes}"
            probe_abs="$DEPLOY_DIR/${probe_host_dir#./}"
            mkdir -p "$probe_abs"
            find "$probe_abs" -name 'probes_*.jsonl' -type f -delete 2>/dev/null || true
            echo "=== Probes ON: writing to $probe_abs ==="
            echo "    after run:  scripts/probe-tail.py --dir $probe_abs"
        fi

        pushd "$DEPLOY_DIR" >/dev/null
        echo "=== docker compose up (10 peers + inspector) ==="
        docker compose up -d
        popd >/dev/null

        # Wait until the inspector container publishes its port.
        for _ in $(seq 1 60); do
            if (echo >/dev/tcp/127.0.0.1/$INSPECTOR_PORT) &>/dev/null; then
                break
            fi
            sleep 0.5
        done
        open_browser "http://localhost:$INSPECTOR_PORT/"

        echo ""
        echo "--- Running. Ctrl-C to stop ---"
        echo "Inspector logs: docker logs -f civilian-inspector"
        trap 'echo; echo "Stopping..."; \
              (cd "$DEPLOY_DIR" && docker compose down)' INT TERM
        # Keep the script in the foreground so the trap fires on Ctrl-C.
        # Poll the compose stack; exits naturally if all containers stop.
        while (cd "$DEPLOY_DIR" && docker compose ps --services --filter \
                status=running | grep -q .); do
            sleep 5
        done
        ;;

    k8s)
        command -v kubectl &>/dev/null \
            || { echo "kubectl not found"; exit 1; }
        if ! command -v minikube &>/dev/null; then
            echo "minikube not installed; see https://minikube.sigs.k8s.io/docs/start/" >&2
            exit 1
        fi
        if ! minikube status &>/dev/null; then
            echo "=== Starting Minikube ==="
            minikube start
        fi
        echo "=== Applying manifests to $NAMESPACE ==="
        kubectl apply -f "$DEPLOY_DIR/kubernetes/namespace.yaml"
        kubectl apply -f "$DEPLOY_DIR/kubernetes/scenario-config.yaml"
        for f in "$DEPLOY_DIR"/kubernetes/*.yaml; do
            case "$(basename "$f")" in
                namespace.yaml|scenario-config.yaml) ;;
                *) kubectl apply -f "$f";;
            esac
        done

        echo "=== Waiting for pods in $NAMESPACE ==="
        kubectl wait --for=condition=Ready pods \
            --all --namespace "$NAMESPACE" --timeout=120s || true

        echo "Starting inspector on :$INSPECTOR_PORT"
        python3 -m autonomous_trust.inspector \
            --demo-civilian \
            --port "$INSPECTOR_PORT" \
            --namespace "$NAMESPACE" \
            &>/tmp/demo-inspector.log &
        INSPECTOR_PID=$!
        for _ in $(seq 1 30); do
            if (echo >/dev/tcp/127.0.0.1/$INSPECTOR_PORT) &>/dev/null; then
                break
            fi
            sleep 0.5
        done
        open_browser "http://localhost:$INSPECTOR_PORT/"

        echo ""
        echo "--- Running. Ctrl-C to tear down ---"
        trap 'echo; echo "Stopping..."; \
              kill $INSPECTOR_PID 2>/dev/null || true; \
              kubectl delete namespace "$NAMESPACE" --ignore-not-found' INT TERM
        wait $INSPECTOR_PID
        ;;

    *)
        echo "Unhandled mode: $BACKEND_MODE" >&2
        exit 2
        ;;
esac
