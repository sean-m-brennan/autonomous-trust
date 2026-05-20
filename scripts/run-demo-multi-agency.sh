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
# One-command launcher for the multi-agency disaster-response demo.
#
# What it does:
#   1. Picks a backend:
#        --tilt (default)              -> Tilt manages a kube context
#                                         (live image rebuild on save)
#        --compose                     -> docker compose up
#        --k8s                         -> minikube + kubectl apply
#                                         (one-shot, no Tilt)
#        --playback FILE               -> inspector only, replay canned JSON
#   2. Regenerates docker-compose.yaml + kubernetes/ manifests from the
#      DisasterResponseScenario definition (Tilt does this itself; the
#      compose/k8s branches call disaster_response_compose directly).
#   3. Opens a browser to the inspector dashboard once it's serving.
#
# The generated outputs live under ./deploy/multi_agency/ by default so the
# tracked tree isn't polluted; clean with:
#     scripts/run-demo-multi-agency.sh --clean
#
# Examples:
#     scripts/run-demo-multi-agency.sh                      # tilt, default
#     scripts/run-demo-multi-agency.sh --compose            # docker compose
#     scripts/run-demo-multi-agency.sh --k8s --namespace disaster-demo
#     scripts/run-demo-multi-agency.sh --playback recording.json

set -euo pipefail

# --- Paths ---------------------------------------------------------------

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$here"

# Put the namespace-package sources on PYTHONPATH so host-side python can
# import autonomous_trust.{evaluation,inspector,...} without a pip install.
# Repo root is also on the path so `python -m examples.multi_agency`
# resolves to examples/multi_agency/__main__.py.
AT_SRC_PATHS="$here/src/autonomous-trust:$here/src/autonomous-trust-evaluation:$here/src/autonomous-trust-inspector:$here/src/autonomous-trust-services:$here/src/autonomous-trust-simulator"
export PYTHONPATH="${AT_SRC_PATHS}:${here}${PYTHONPATH:+:$PYTHONPATH}"

# Force native backend on the host so it matches the peer containers.
# Overridable for debug; fallback to _python still applies per-module
# via the core redirector.
export AUTONOMOUS_TRUST_BACKEND="${AUTONOMOUS_TRUST_BACKEND:-native}"

DEPLOY_DIR="${DEPLOY_DIR:-deploy/multi_agency}"
NAMESPACE="${NAMESPACE:-disaster-demo}"
INSPECTOR_PORT="${INSPECTOR_PORT:-8050}"
REGISTRY="${REGISTRY:-}"
IMAGE_TAG="${IMAGE_TAG:-:dev}"
IMAGE_NAME="${IMAGE_NAME:-autonomous-trust}"
# Peer image (disaster overlay = base + evaluation + services packages).
# The compose generator references this name for every peer service.
PEER_IMAGE_NAME="${PEER_IMAGE_NAME:-autonomous-trust-disaster}"
LOG_LEVEL="${LOG_LEVEL:-info}"
BACKEND_MODE="tilt"
PLAYBACK_FILE=""
RECORD_FILE=""
TILT_LOG="${TILT_LOG:-/tmp/multi-agency-tilt.log}"

# Default probes to ON for the demo so every peer + the inspector emits
# JSONL counters into deploy/multi_agency/at-probes. Export so the compose
# generator (which reads os.environ['AT_PROBES']) bakes the env vars +
# volume mount into every service. Override with AT_PROBES= to disable.
export AT_PROBES="${AT_PROBES:-1}"

# --- Argument parsing ----------------------------------------------------

usage() {
    cat <<EOF
Usage: $0 [options]

Deployment modes (pick one):
  --tilt                     Tilt-managed (default; live rebuild on save)
  --compose                  docker compose (one-shot)
  --k8s                      Minikube + kubectl (one-shot)
  --playback <FILE>          Inspector only; replay events from FILE.json
  --record <FILE>            Inspector only (no cluster); run the scripted
                             scenario and capture events to FILE.json on
                             Ctrl-C. Output is consumable by --playback.
  --teardown                 Run \`tilt down\` against the multi-agency
                             stack + host-side process reaping, then
                             exit.  Use when a previous run left state
                             behind.

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
        --tilt)         BACKEND_MODE="tilt";    shift;;
        --compose)      BACKEND_MODE="compose"; shift;;
        --k8s)          BACKEND_MODE="k8s";     shift;;
        --teardown)     BACKEND_MODE="teardown"; shift;;
        --playback)     BACKEND_MODE="playback"; PLAYBACK_FILE="$2"; shift 2;;
        --record)       BACKEND_MODE="record";   RECORD_FILE="$2";   shift 2;;
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
    exec python3 -m examples.multi_agency \
        --playback "$PLAYBACK_FILE" \
        --port "$INSPECTOR_PORT"
fi

if [[ "$BACKEND_MODE" == "record" ]]; then
    if [[ -z "$RECORD_FILE" ]]; then
        echo "Missing --record FILE argument" >&2
        exit 1
    fi
    # Recording is a host-side scripted run: no cluster, no peers, just
    # the scenario timeline ticking under the inspector. EventRecorder
    # captures every PhaseEvent and writes JSON on Ctrl-C (atexit hook
    # in MultiAgencyDemo._save_recording).
    mkdir -p "$(dirname -- "$RECORD_FILE")"
    echo "=== Inspector-only recording mode ==="
    echo "    Output: $RECORD_FILE (written on Ctrl-C)"
    exec python3 -m examples.multi_agency \
        --record "$RECORD_FILE" \
        --port "$INSPECTOR_PORT" \
        --log-level "$LOG_LEVEL"
fi

# --- Generate manifests --------------------------------------------------
# Skipped in tilt mode — the multi_agency.tiltfile owns regeneration via a
# local_resource and re-runs it whenever the scenario sources change.

if [[ "$BACKEND_MODE" != "tilt" && "$BACKEND_MODE" != "teardown" ]]; then
    echo "=== Generating manifests under $DEPLOY_DIR ==="
    python3 -m autonomous_trust.evaluation.scenarios.disaster_response_compose \
        --out "$DEPLOY_DIR" \
        --namespace "$NAMESPACE" \
        --registry "$REGISTRY" \
        --image "$PEER_IMAGE_NAME" \
        --image-tag "$IMAGE_TAG" \
        --log-level "$LOG_LEVEL"
fi

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

# Block until a URL serves HTTP (not just until the port is bound).
# The compose port-publish proxy and the k8s service IP come up
# immediately, so a TCP-only probe fires before Dash is ready inside
# the container — the browser then opens to a "connection reset".
# Inspector's container also sleeps STARTUP_DELAY=45s before launching
# python, so the inspector wait needs a generous timeout. Fast services
# (e.g. the Tilt UI) can pass a short timeout instead.
#
# Usage: wait_for_http <url> [timeout_sec] [label] [tcp_fallback_port]
wait_for_http() {
    local url="$1"
    local timeout="${2:-180}"
    local label="${3:-service}"
    local tcp_port="${4:-}"
    local start now elapsed code last_progress=0
    start=$(date +%s)
    if ! command -v curl &>/dev/null; then
        # Fall back to TCP probe if curl is missing; less precise but
        # better than nothing.
        if [[ -z "$tcp_port" ]]; then
            echo "curl missing and no tcp_port supplied; cannot probe $url" >&2
            return 1
        fi
        for _ in $(seq 1 $((timeout * 2))); do
            (echo >/dev/tcp/127.0.0.1/"$tcp_port") &>/dev/null && return 0
            sleep 0.5
        done
        return 1
    fi
    while :; do
        # `--max-time 2` keeps each probe short so we can iterate; we
        # want the response code, not the body. 200/302 means Dash is
        # up; anything else (000 connection refused, 502 from a docker
        # proxy with no backend, 503 from Quart still booting) means
        # keep waiting.
        code=$(curl --silent --output /dev/null --max-time 2 \
                    --write-out '%{http_code}' "$url" || echo "000")
        if [[ "$code" == "200" || "$code" == "302" ]]; then
            return 0
        fi
        now=$(date +%s)
        elapsed=$(( now - start ))
        if (( elapsed >= timeout )); then
            return 1
        fi
        # Progress line every 10s so the user knows we're alive.
        if (( elapsed - last_progress >= 10 )); then
            echo "  ... waiting for $label (${elapsed}s, http=$code)"
            last_progress=$elapsed
        fi
        sleep 1
    done
}

# Backwards-compatible thin wrapper for the inspector-specific call sites.
wait_for_inspector_http() {
    wait_for_http "$1" "${2:-180}" "inspector" "$INSPECTOR_PORT"
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
    pkill -f "examples\\.multi_agency" 2>/dev/null || true
}

# Safety net: ensure leftover inspector / AT-worker processes are reaped
# even if the python-side atexit handler can't run (SIGKILL, segfault,
# or the user killing this script before the launched process exits).
# The python-side cleanup in inspector.__main__ is the primary mechanism;
# this trap catches the residual.
trap 'cleanup_inspector_procs' EXIT

# Make sure a local Kubernetes cluster is up before any backend that
# needs one (tilt, k8s).  Requires minikube on PATH; starts it if it
# isn't already running.  Exits 1 if minikube isn't installed so the
# caller doesn't proceed into a "no kube context" failure further down.
ensure_minikube_running() {
    if ! command -v minikube &>/dev/null; then
        echo "minikube not installed; see https://minikube.sigs.k8s.io/docs/start/" >&2
        echo "(or rerun with --compose for the docker-compose backend)" >&2
        exit 1
    fi
    if ! minikube status &>/dev/null; then
        echo "=== Starting Minikube ==="
        minikube start
    fi
}

# Switch to the cluster's docker daemon if we're targeting minikube, so
# subsequent `docker build` lands where pods can pull from. No-op (and
# silent) on other contexts; callers must accept that ImagePullBackOff
# is a possibility on non-minikube clusters without a registry.
use_cluster_docker_env() {
    if command -v minikube &>/dev/null && minikube status &>/dev/null; then
        eval "$(minikube docker-env 2>/dev/null)" || true
    fi
}

# Build any of the three demo images that aren't present in the *active*
# docker daemon. Call use_cluster_docker_env() first if you want builds
# to target the cluster's daemon (k8s/tilt path); skip it for compose so
# host docker keeps the images.
#
# Tilt's own docker_build skips when its content-hash cache says the
# image is current and doesn't notice when the user `docker rmi`s the
# image out from under it; this helper makes `rmi + relaunch` produce a
# fresh build regardless of backend.
ensure_demo_images() {
    local full_ref peer_ref inspector_ref
    full_ref="${REGISTRY}${IMAGE_NAME}${IMAGE_TAG}"
    peer_ref="${REGISTRY}${PEER_IMAGE_NAME}${IMAGE_TAG}"
    inspector_ref="${REGISTRY}autonomous-trust-inspector${IMAGE_TAG}"

    if ! docker image inspect "$full_ref" &>/dev/null; then
        echo "=== Image $full_ref not found — building ==="
        docker build \
            -t "$full_ref" \
            -f "$here/src/autonomous-trust/Dockerfile-native" \
            "$here"
    fi
    if ! docker image inspect "$peer_ref" &>/dev/null; then
        echo "=== Image $peer_ref not found — building ==="
        docker build \
            --build-arg "BASE_IMAGE=$full_ref" \
            -t "$peer_ref" \
            -f "$here/src/autonomous-trust-evaluation/Dockerfile" \
            "$here"
    fi
    if ! docker image inspect "$inspector_ref" &>/dev/null; then
        echo "=== Image $inspector_ref not found — building ==="
        docker build \
            --build-arg "BASE_IMAGE=$full_ref" \
            -t "$inspector_ref" \
            -f "$here/src/autonomous-trust-inspector/Dockerfile" \
            "$here"
    fi
}

case "$BACKEND_MODE" in
    tilt)
        command -v tilt &>/dev/null \
            || { echo "tilt not found; install from https://docs.tilt.dev/" >&2; exit 1; }
        command -v kubectl &>/dev/null \
            || { echo "kubectl not found (Tilt needs a working kube context)" >&2; exit 1; }

        # Tilt needs a live kube context; bring up minikube if it isn't
        # already running so the user doesn't hit "no configuration has
        # been provided" inside the Tiltfile.
        ensure_minikube_running

        # Preflight image build: make `docker rmi <imgs> && relaunch`
        # produce a fresh build regardless of Tilt's own caching. We
        # build into the cluster's daemon (minikube docker-env) so pods
        # can find the image without a registry round-trip.
        echo "=== Preflight image check ==="
        use_cluster_docker_env
        ensure_demo_images

        echo "=== Starting Tilt (multi-agency variant) ==="
        echo "    Logs: tail -f $TILT_LOG"
        echo "    UI:   http://localhost:10350"

        # Foreground-cleanup is the contract of this launcher (one-command
        # demo, Ctrl-C tears down). Tilt itself is happy to be backgrounded
        # because non-TTY stdout switches it to streaming-log mode.
        tilt up -- \
            --variant=multi-agency \
            --namespace="$NAMESPACE" \
            --log-level="$LOG_LEVEL" \
            &>"$TILT_LOG" &
        TILT_PID=$!

        # Trap before the wait so any failure during readiness still
        # tears the cluster state down.  Split traps: EXIT does the
        # actual cleanup; INT/TERM just call `exit` so Ctrl-C
        # interrupts the wait_for_inspector_http loop below (its
        # `sleep 1` is interruptible, but without an explicit exit
        # bash resumes the script and the loop keeps polling for the
        # full timeout).
        trap 'kill $TILT_PID 2>/dev/null || true; \
              wait $TILT_PID 2>/dev/null || true; \
              tilt down -- --variant=multi-agency --namespace="$NAMESPACE" \
                  --log-level="$LOG_LEVEL" &>>"$TILT_LOG" || true' EXIT
        trap 'echo; echo "Stopping Tilt..."; exit 130' INT
        trap 'echo; echo "Stopping Tilt..."; exit 143' TERM

        # Open the Tilt control UI as soon as it's serving so the user
        # can watch image builds + pod rollout progress while the
        # inspector pod still boots. The Tilt UI comes up within a few
        # seconds of `tilt up`; cap the wait at 30s so a stuck Tilt
        # doesn't block the rest of startup.
        tilt_ui_url="http://localhost:10350/"
        echo "=== Waiting for Tilt UI at $tilt_ui_url ==="
        if wait_for_http "$tilt_ui_url" 30 "tilt UI" 10350; then
            open_browser "$tilt_ui_url"
        else
            echo "Tilt UI not reachable at $tilt_ui_url within 30s; continuing." >&2
        fi

        echo "=== Waiting for inspector port-forward at http://localhost:$INSPECTOR_PORT/ ==="
        # Image builds + k8s rollout dominate first-run latency; give them
        # 10 minutes before declaring failure. Subsequent runs are seconds.
        if wait_for_inspector_http "http://localhost:$INSPECTOR_PORT/" 600; then
            open_browser "http://localhost:$INSPECTOR_PORT/"
        else
            echo "Inspector did not respond within 10 min." >&2
            echo "Check $TILT_LOG and the Tilt UI at $tilt_ui_url" >&2
        fi

        echo ""
        echo "--- Running. Ctrl-C to tear down ---"
        # Hold the foreground until tilt exits (Ctrl-C path) or it dies.
        wait $TILT_PID
        ;;

    compose)
        command -v docker &>/dev/null \
            || { echo "docker not found"; exit 1; }

        # Build the base, disaster-peer, and multi-agency-inspector images
        # in the host docker daemon (compose runs there too). The peer
        # image extends the base with autonomous_trust.evaluation and
        # .services so disaster_response_demo can import; the inspector
        # image extends the base with Dash deps + sibling AT subpackages.
        ensure_demo_images

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

        echo "=== Waiting for inspector HTTP to come up ==="
        if wait_for_inspector_http "http://localhost:$INSPECTOR_PORT/" 180; then
            open_browser "http://localhost:$INSPECTOR_PORT/"
        else
            echo "Inspector did not respond within 180s; opening anyway."
            echo "Check 'docker logs multi-agency-inspector' for startup errors."
            open_browser "http://localhost:$INSPECTOR_PORT/"
        fi

        echo ""
        echo "--- Running. Ctrl-C to stop ---"
        echo "Inspector logs: docker logs -f multi-agency-inspector"
        # EXIT handles teardown; INT/TERM just exit so Ctrl-C
        # propagates immediately instead of being absorbed by the
        # signal handler and the surrounding loop.  Chain the global
        # `cleanup_inspector_procs` so we don't lose host-side
        # process reaping by overriding the EXIT trap.
        trap '(cd "$DEPLOY_DIR" && docker compose down) || true; \
              cleanup_inspector_procs' EXIT
        trap 'echo; echo "Stopping..."; exit 130' INT
        trap 'echo; echo "Stopping..."; exit 143' TERM
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
        ensure_minikube_running
        echo "=== Applying manifests to $NAMESPACE ==="
        kubectl apply -f "$DEPLOY_DIR/kubernetes/namespace.yaml"
        kubectl apply -f "$DEPLOY_DIR/kubernetes/scenario-config.yaml"
        for f in "$DEPLOY_DIR"/kubernetes/*.yaml; do
            case "$(basename "$f")" in
                namespace.yaml|scenario-config.yaml) ;;
                *) kubectl apply -f "$f";;
            esac
        done

        # Make the cluster's docker daemon the build target so locally-
        # built images are visible inside pods without a registry push.
        use_cluster_docker_env
        ensure_demo_images

        echo "=== Waiting for pods in $NAMESPACE ==="
        # Wait for peers to come up first so the inspector doesn't time
        # out its choose_group window before peers are listening.
        kubectl wait --for=condition=Ready pods \
            --all --namespace "$NAMESPACE" --timeout=180s || true

        # Resolve the inspector NodePort URL via minikube. The inspector
        # itself runs in-cluster as a Deployment + Service emitted by
        # disaster_response_compose; we just need the host-side URL.
        echo "=== Resolving inspector service URL ==="
        inspector_url=$(minikube service multi-agency-inspector \
            -n "$NAMESPACE" --url 2>/dev/null | head -1)
        if [[ -z "$inspector_url" ]]; then
            echo "minikube service URL unavailable; falling back to NodePort lookup"
            node_port=$(kubectl get svc multi-agency-inspector \
                -n "$NAMESPACE" -o jsonpath='{.spec.ports[0].nodePort}' 2>/dev/null)
            node_ip=$(minikube ip 2>/dev/null)
            if [[ -n "$node_ip" && -n "$node_port" ]]; then
                inspector_url="http://$node_ip:$node_port"
            else
                echo "Could not determine inspector URL; check 'kubectl get svc -n $NAMESPACE'." >&2
                exit 1
            fi
        fi

        echo "=== Waiting for inspector HTTP at $inspector_url ==="
        if wait_for_inspector_http "$inspector_url/" 180; then
            open_browser "$inspector_url/"
        else
            echo "Inspector did not respond within 180s; opening anyway."
            echo "Check 'kubectl logs -n $NAMESPACE deployment/multi-agency-inspector'."
            open_browser "$inspector_url/"
        fi

        echo ""
        echo "--- Running. Ctrl-C to tear down ---"
        echo "Inspector logs: kubectl logs -n $NAMESPACE -f deployment/multi-agency-inspector"
        # EXIT does the namespace teardown; INT/TERM just exit so
        # Ctrl-C breaks out of the polling loop below immediately.
        # Chain `cleanup_inspector_procs` so the global EXIT
        # trap's host-side reaping isn't lost when we override.
        trap 'kubectl delete namespace "$NAMESPACE" --ignore-not-found || true; \
              cleanup_inspector_procs' EXIT
        trap 'echo; echo "Stopping..."; exit 130' INT
        trap 'echo; echo "Stopping..."; exit 143' TERM
        # Hold the script open until the namespace goes away (Ctrl-C
        # path) or the inspector deployment scales to zero.
        while kubectl get deployment multi-agency-inspector \
                -n "$NAMESPACE" &>/dev/null; do
            sleep 5
        done
        ;;

    teardown)
        # Best-effort cleanup for a stuck or abandoned run.  Idempotent:
        # missing tilt, missing namespace, and missing host-side procs
        # are all fine and silently ignored.
        if command -v tilt &>/dev/null; then
            echo "=== tilt down (multi-agency / $NAMESPACE) ==="
            tilt down -- \
                --variant=multi-agency \
                --namespace="$NAMESPACE" \
                --log-level="$LOG_LEVEL" || true
        else
            echo "tilt not on PATH; skipping 'tilt down'"
        fi
        echo "=== Reaping host-side inspector processes ==="
        cleanup_inspector_procs
        echo "Teardown complete."
        ;;

    *)
        echo "Unhandled mode: $BACKEND_MODE" >&2
        exit 2
        ;;
esac
