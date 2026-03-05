#!/usr/bin/env bash
set -euo pipefail

# --- Parse arguments ---

BACKEND="native"
NUM_NODES=""
POSITIONAL_ARGS=()

usage() {
    echo "Usage: $0 [--python] [NUM_NODES]"
    echo ""
    echo "  --python    Use pure-Python backend (default: native C backend)"
    echo "  NUM_NODES   Number of peer nodes to start (default: 2)"
    exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --python)
            BACKEND="python"
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

PROTO_SRC="src/protobuf"
PROTO_PY_DIR="src/autonomous-trust"
PROTO_PY="$PROTO_PY_DIR/autonomous_trust/core/protobuf"
PROTO_TARGET="$PROTO_PY_DIR/autonomous_trust/core/_python/protobuf"
if [ ! -d "$PROTO_PY" ] || [ -z "$(find "$PROTO_PY" -name '*_pb2.py' 2>/dev/null)" ]; then
    echo "Generating protobuf Python files..."
    protoc --python_out="$PROTO_PY_DIR" -I "$PROTO_SRC" \
        $(find "$PROTO_SRC" -name "*.proto")

    # Create __init__.py files in all generated subdirs
    find "$PROTO_PY" -type d -exec touch {}/__init__.py \;
    touch "$PROTO_PY/__init__.py"
    echo "Protobuf files generated."
    mkdir -p $PROTO_TARGET
    cp -R $PROTO_PY/. $PROTO_TARGET/
    rm -rf $PROTO_PY
fi

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

cleanup() {
    echo ""
    echo "Shutting down Tilt..."
    tilt down
}
trap cleanup EXIT

echo "Starting AutonomousTrust demo with $NUM_NODES nodes..."
tilt up -- --num-nodes="$NUM_NODES" --backend="$BACKEND"
