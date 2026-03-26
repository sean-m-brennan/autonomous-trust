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
# Run AutonomousTrust demo via Tilt.

set -euo pipefail

# --- Run everything relative to the repo root ---

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$here" || exit 1

# --- Parse arguments ---

BACKEND="native"
LOG_LEVEL="warning"
NUM_NODES=""
POSITIONAL_ARGS=()

usage() {
    echo "Usage: $0 [--python] [--log-level LEVEL] [NUM_NODES]"
    echo ""
    echo "  --python          Use pure-Python backend (default: native C backend)"
    echo "  -v[v[v]]          Increase logging verbosity: to info, debug, then verbose"
    echo "  NUM_NODES         Number of peer nodes to start (default: 2)"
    exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --py|--python)
            BACKEND="python"
            shift
            ;;
        -v)
            LOG_LEVEL="info"
            shift
            ;;
        -vv)
            LOG_LEVEL="debug"
            shift
            ;;
        -vvv)
            LOG_LEVEL="verbose"
            shift
            ;;
        -h|--help)
            usage
            ;;
        -*)
            echo "Unknown option: $1" >&2
            usage 1
            ;;
        *)
            POSITIONAL_ARGS+=("$1")
            shift
            ;;
    esac
done

NUM_NODES="${POSITIONAL_ARGS[0]:-2}"

# --- Check prerequisites ---

if ! command -v docker &>/dev/null; then
    echo "ERROR: docker is not installed or not in PATH"
    exit 1
fi

if ! command -v tilt &>/dev/null; then
    echo "Installing Tilt..."
    curl -fsSL https://raw.githubusercontent.com/tilt-dev/tilt/master/scripts/install.sh | bash
fi

# --- Generate protobuf Python files if needed ---

scripts/build.sh --py

# --- Detect proxy settings ---

if [ -n "${http_proxy:-}" ]; then
    export http_proxy
fi
if [ -n "${https_proxy:-}" ]; then
    export https_proxy
fi
if [ -n "${no_proxy:-}" ]; then
    export no_proxy
fi

# Detect CA cert for proxy
CERT_PATH="/usr/local/share/ca-certificates/proxy-ca.crt"
if [ -f "$CERT_PATH" ]; then
    export CERT_CONTENT
    CERT_CONTENT="$(cat "$CERT_PATH")"
fi

# --- Select Dockerfile based on backend ---

if [ "$BACKEND" = "native" ]; then
    DOCKERFILE="src/autonomous-trust/Dockerfile-native"
    echo "Backend: native (C library via CFFI)"
else
    DOCKERFILE="src/autonomous-trust/Dockerfile-lite"
    echo "Backend: python (pure Python)"
fi

export AUTONOMOUS_TRUST_BACKEND="$BACKEND"

# --- Launch Tilt ---

echo "Starting AutonomousTrust demo with $NUM_NODES nodes (log level: $LOG_LEVEL)..."
tilt up -- --num-nodes="$NUM_NODES" --backend="$BACKEND" --log-level="$LOG_LEVEL" $@
# Blocks until killed (Ctl-C)

tilt down -- $@