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
# Multi-node Docker integration test for autonomous-trust.
#
# Builds devel + test containers, creates a macvlan Docker network,
# launches N autonomous-trust nodes, then runs the test suite against
# the live cluster.
#
# Usage:
#   ./test-integration.sh                  # 4 nodes, default
#   ./test-integration.sh -n 6             # 6 nodes
#   ./test-integration.sh --debug          # debug mode (keeps terminal open)
#   ./test-integration.sh --quick          # skip container rebuild
#   ./test-integration.sh --shell          # drop into bash in test container
#   ./test-integration.sh --force          # rebuild containers + network from scratch

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SRC_DIR="$REPO_DIR/src"
AT_DIR="$SRC_DIR/autonomous-trust"

# Defaults (from config/config.py)
IMAGE_NAME="autonomous-trust"
NETWORK_NAME="autonomous-trust-net"
NETWORK_TYPE="macvlan"
IPV4_SUBNET="172.27.3.0/24"
NUM_NODES=4
DEBUG=false
QUICK=false
FORCE=false
SHELL_MODE=false
REGISTRY_URL=""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RESET='\033[0m'

info()  { echo -e "${GREEN}[test]${RESET} $*"; }
warn()  { echo -e "${YELLOW}[test]${RESET} $*"; }
error() { echo -e "${RED}[test]${RESET} $*" >&2; }

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        -n|--nodes)   NUM_NODES="$2"; shift 2 ;;
        --debug|-d)      DEBUG=true; shift ;;
        --quick|-q)      QUICK=true; shift ;;
        --force|-f)      FORCE=true; shift ;;
        --shell)      SHELL_MODE=true; shift ;;
        --registry)   REGISTRY_URL="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo "  -n, --nodes N     Number of test nodes (default: 4)"
            echo "  --debug           Debug mode (build + run verbose)"
            echo "  --quick           Skip container rebuild"
            echo "  --force           Force rebuild containers and network"
            echo "  --shell           Drop into bash in test container"
            echo "  --registry URL    Docker registry URL prefix"
            exit 0 ;;
        *) error "Unknown option: $1"; exit 1 ;;
    esac
done

# ---------------------------------------------------------------------------
# Preflight checks
# ---------------------------------------------------------------------------
if ! command -v docker &>/dev/null; then
    error "Docker is required but not found"
    exit 1
fi

# Source local registry helpers (pull-or-build fallback)
source "$SCRIPT_DIR/local-registry.sh" 2>/dev/null || true

# ---------------------------------------------------------------------------
# Build containers (pull from registry or build as fallback)
# ---------------------------------------------------------------------------
build_containers() {
    if $FORCE; then
        # Force rebuild via build-docker.sh (which also pushes to registry)
        local build_args=(--force)
        if $DEBUG; then
            build_args+=(--debug)
        fi
        if [[ -n "$REGISTRY_URL" ]]; then
            build_args+=(--registry "$REGISTRY_URL")
        fi
        "$SCRIPT_DIR/build-docker.sh" "${build_args[@]}" devel test
    else
        # Pull from local registry, build as fallback
        require_image "${IMAGE_NAME}-devel" devel
        require_image "${IMAGE_NAME}-test" devel test
    fi
}

# ---------------------------------------------------------------------------
# Docker network
# ---------------------------------------------------------------------------
create_network() {
    if docker network ls --format '{{.Name}}' | grep -q "^${NETWORK_NAME}\$"; then
        if $FORCE; then
            info "Removing existing network $NETWORK_NAME ..."
            docker network rm "$NETWORK_NAME" 2>/dev/null || true
            docker network prune -f 2>/dev/null || true
        else
            info "Network $NETWORK_NAME already exists"
            return 0
        fi
    fi

    local prefix
    prefix="$(echo "$IPV4_SUBNET" | cut -d'.' -f1-3)"
    local mask
    mask="$(echo "$IPV4_SUBNET" | cut -d'/' -f2)"

    local gateway="${prefix}.131"
    local ip_range="${prefix}.132/$((mask + 1))"

    # Detect default route device
    local device
    device="$(ip -o -4 route show default | awk '{print $5}' | head -1)"

    info "Creating Docker network $NETWORK_NAME (${NETWORK_TYPE}) ..."
    docker network create \
        --driver "$NETWORK_TYPE" \
        --subnet "$IPV4_SUBNET" \
        --gateway "$gateway" \
        --ip-range "$ip_range" \
        --opt "parent=$device" \
        "$NETWORK_NAME"
}

# ---------------------------------------------------------------------------
# Run nodes + test
# ---------------------------------------------------------------------------
cleanup() {
    info "Stopping containers ..."
    for n in $(seq 1 "$NUM_NODES"); do
        docker stop "at-$n" 2>/dev/null || true
    done
    docker stop "at-test" 2>/dev/null || true
    # Clean up IP file
    rm -f "$AT_DIR/docker_ips"
}

run_test() {
    local gateway
    gateway="$(ip -o -4 route show default | awk '{print $3}' | head -1)"

    local ip_file="$AT_DIR/docker_ips"
    : > "$ip_file"
    mkdir -p "$AT_DIR/coverage"

    trap cleanup EXIT

    # Launch N nodes
    info "Launching $NUM_NODES nodes ..."
    for n in $(seq 1 "$NUM_NODES"); do
        local ident="at-$n"
        docker run --rm -d \
            --name "$ident" \
            -h "$ident" \
            --network "$NETWORK_NAME" \
            --cap-add NET_ADMIN \
            -e "ROUTER=$gateway" \
            -e 'AUTONOMOUS_TRUST_ARGS="--live --test"' \
            "$IMAGE_NAME-devel"

        # Stagger startup (1-5s random)
        sleep $(( (RANDOM % 5) + 1 ))
    done

    sleep 1

    # Collect container IPs
    for n in $(seq 1 "$NUM_NODES"); do
        local ip
        ip="$(docker inspect --format '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "at-$n")"
        echo "$ip" >> "$ip_file"
    done
    info "Node IPs: $(tr '\n' ' ' < "$ip_file")"

    # Mount paths for test container
    local mount_args=()
    for mnt in tests coverage tox.ini requirements.txt tests_require.txt docker_ips; do
        local host_path="$AT_DIR/$mnt"
        if [ -e "$host_path" ]; then
            mount_args+=(-v "$host_path:/app/$mnt")
        fi
    done

    # tools/ lives at the repo root, not under $AT_DIR, and is not baked into
    # the image. tests/a_unit/test_piv_verifier.py and test_operator_activate.py
    # import tools.provision_zta_certs to mint their PKI fixtures; they locate
    # it by searching upward for tools/provision_zta_certs.py, which finds
    # /app once this is mounted.
    if [ -e "$REPO_DIR/tools" ]; then
        mount_args+=(-v "$REPO_DIR/tools:/app/tools")
    fi

    # Run test container
    local run_args=(
        --rm
        --name at-test
        -h at-test
        --network "$NETWORK_NAME"
        --cap-add NET_ADMIN
        -u "$(id -u):$(id -g)"
        -e "ROUTER=$gateway"
        -e 'AUTONOMOUS_TRUST_ARGS="--live --test"'
        # tox defaults its work dir to {toxinidir}/.tox, i.e. /app/.tox. We
        # run as the host uid (above), but /app is owned by the image's
        # `user` (Dockerfile-devel: useradd -U user -d /app), so unless those
        # uids happen to match, tox dies with EACCES creating .tox/.pkg. Only
        # the individually-mounted paths below are host-owned and writable.
        # Point the work dir at container-local /tmp instead: it also keeps
        # .tox out of the source tree, which build-docker.sh otherwise has to
        # stash away before conda-build walks it.
        -e "TOX_WORK_DIR=/tmp/.tox"
        # The macvlan segment above has no route to PyPI (its gateway is
        # synthesized from the subnet prefix), and it does not need one: the
        # image's conda env already supplies every entry of requirements.txt
        # (environment.yml) and tests_require.txt (devel_environ.yml). Let
        # tox's venv see those, so pip resolves each requirement as already
        # satisfied and never reaches for the network -- the same "the conda
        # env IS the environment under test" reasoning as CONFORMANCE_SKIP_TOX
        # in test-conformance.sh, but without giving up tox.ini as the source
        # of the pytest invocation. PIP_NO_INDEX turns any genuine gap into an
        # immediate, legible error instead of five connection retries.
        -e "VIRTUALENV_SYSTEM_SITE_PACKAGES=true"
        -e "PIP_NO_INDEX=1"
        # Skip tox's sdist build for the same reason we skip its dep install:
        # Dockerfile-devel already ran `poetry install` into the conda env, so
        # the project is importable there and the line above exposes it to the
        # testenv. Building it again would need poetry-core in a PEP 517 build
        # env -- and conda's `poetry` vendors poetry-core rather than shipping
        # a separate distribution pip can see, so offline that build cannot be
        # satisfied. Nothing is lost: pyproject.toml is not among the mounted
        # paths, so tox would have been packaging the image's baked-in copy
        # of the source, which is exactly what poetry installed.
        -e "TOX_OVERRIDE=testenv.package=skip"
        # tests/ is bind-mounted from the host, so its __pycache__ holds .pyc
        # files compiled there. Their header (source mtime + size) still
        # matches, so the container serves them instead of recompiling, and
        # tracebacks then cite the host path -- which does not exist here, so
        # pytest prints `???` for the source line. Relocating the cache makes
        # the host's __pycache__ invisible; PYTHONDONTWRITEBYTECODE does NOT
        # (it stops writes, not reads). This also keeps the container from
        # dropping its own uid's .pyc files into the host source tree.
        -e "PYTHONPYCACHEPREFIX=/tmp/pycache"
        # coverage puts its SQLite data file in the CWD, i.e. /app, which this
        # uid cannot write -- the same ownership mismatch that TOX_WORK_DIR
        # works around, surfacing at the end of the run as an INTERNALERROR
        # ("unable to open database file") after the tests have already
        # passed. Only the raw data file moves; --cov-report=html:coverage
        # still resolves against the CWD, so the report lands in the mounted
        # coverage/ dir and reaches the host as before. /tmp matches the
        # previous lifetime too: /app was never mounted, so the data file has
        # always died with the container.
        -e "COVERAGE_FILE=/tmp/.coverage"
        "${mount_args[@]}"
    )

    if $SHELL_MODE; then
        info "Dropping into test container shell ..."
        # Interactive diagnostic session: the shell's status says nothing about
        # the tests, so it never fails the run.
        docker run -it "${run_args[@]}" "${IMAGE_NAME}-test" /bin/bash || true
        info "Test container shell closed"
        return 0
    fi

    info "Running test suite ..."
    local rc=0
    docker run -it "${run_args[@]}" "${IMAGE_NAME}-test" || rc=$?

    if [ "$rc" -ne 0 ]; then
        error "Integration tests FAILED (test container exit $rc)"
        error "Full test output: $AT_DIR/tests/tox.log"
        return "$rc"
    fi

    info "Integration test complete"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    info "autonomous-trust integration test ($NUM_NODES nodes)"
    echo

    if ! $QUICK; then
        build_containers
    fi

    create_network
    run_test
}

main
