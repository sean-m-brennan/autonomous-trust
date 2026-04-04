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
# Docker-based fleet management integration test.
#
# Spins up 3 AutonomousTrust C nodes on a Docker bridge network.
# Node 1 injects a self-referencing update proposal.
# Verifies: peer discovery, Paxos consensus, chunked artifact transfer.
#
# Usage:
#   ./test-docker-fleet.sh                  # full test
#   ./test-docker-fleet.sh --skip-build     # reuse existing Docker image
#   ./test-docker-fleet.sh --keep           # don't tear down containers

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
WORK_DIR="$SCRIPT_DIR/.test-docker-fleet"
IMAGE_NAME="autonomous-trust-c"
NETWORK_NAME="at-fleet-test"
SUBNET="172.28.0.0/24"
NODE_COUNT=3
TIMEOUT=900
SKIP_BUILD=false
KEEP=false

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RESET='\033[0m'

pass() { echo -e "${GREEN}[PASS]${RESET} $*"; }
fail() { echo -e "${RED}[FAIL]${RESET} $*"; }
info() { echo -e "${YELLOW}[test]${RESET} $*"; }

PASSES=0
FAILURES=0

check() {
    local desc="$1"; shift
    if "$@" >/dev/null 2>&1; then
        pass "$desc"
        PASSES=$((PASSES + 1))
    else
        fail "$desc"
        FAILURES=$((FAILURES + 1))
    fi
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-build) SKIP_BUILD=true; shift ;;
        --keep)       KEEP=true; shift ;;
        --nodes|-n)   NODE_COUNT=$2; shift 2 ;;
        -h|--help)
            echo "Usage: $0 [--skip-build] [--keep] [--nodes N]"
            exit 0 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

cleanup() {
    if [ "$KEEP" = true ]; then
        info "Keeping containers (--keep). Clean up with:"
        info "  docker compose -f $WORK_DIR/docker-compose.yml down -v"
        return
    fi
    info "Cleaning up ..."
    docker compose -f "$WORK_DIR/docker-compose.yml" down -v 2>/dev/null || true
    docker network rm "$NETWORK_NAME" 2>/dev/null || true
    rm -rf "$WORK_DIR" 2>/dev/null || true
}
trap cleanup EXIT

# ---------------------------------------------------------------
# Step 1: Build Docker image
# ---------------------------------------------------------------
if [ "$SKIP_BUILD" = false ]; then
    info "Building C Docker image ..."
    docker build --network host \
        -t "$IMAGE_NAME" \
        -f "$PROJECT_ROOT/src/autonomous-trust/Dockerfile-c" \
        "$PROJECT_ROOT"
fi

# ---------------------------------------------------------------
# Step 2: Generate work directory and compose file
# ---------------------------------------------------------------
info "Setting up $NODE_COUNT-node test environment ..."
# Clean previous run's work dir.  Container-created files may be root-owned
# (Docker UID remapping), so fall back to a privileged container for cleanup.
if [ -d "$WORK_DIR" ]; then
    docker compose -f "$WORK_DIR/docker-compose.yml" down -v 2>/dev/null || true
    rm -rf "$WORK_DIR" 2>/dev/null || \
        docker run --rm --privileged -v "$(dirname "$WORK_DIR"):/host" alpine \
            rm -rf "/host/$(basename "$WORK_DIR")" 2>/dev/null || true
fi
mkdir -p "$WORK_DIR"

# Generate per-node data directories
for i in $(seq 1 $NODE_COUNT); do
    mkdir -p "$WORK_DIR/node-$i/var/at"
done

# Generate docker-compose.yml
cat > "$WORK_DIR/docker-compose.yml" <<COMPOSE_EOF
services:
COMPOSE_EOF

for i in $(seq 1 $NODE_COUNT); do
    IP="172.28.0.$((10 + i))"
    DELAY=$(( (i - 1) * 5 ))
    if [ "$i" -eq 1 ]; then
        EXTRA_ARGS="--inject-update"
    else
        EXTRA_ARGS="--test"
    fi
    cat >> "$WORK_DIR/docker-compose.yml" <<NODE_EOF
  at-node-$i:
    image: $IMAGE_NAME
    container_name: at-fleet-node-$i
    hostname: at-node-$i
    user: "$(id -u):$(id -g)"
    cap_add:
      - NET_ADMIN
    environment:
      AUTONOMOUS_TRUST_ROOT: "/"
      ROUTER: "172.28.0.1"
      LOG_LEVEL: "debug"
      STARTUP_DELAY: "$DELAY"
    command: ["$EXTRA_ARGS"]
    volumes:
      - $WORK_DIR/node-$i/var/at:/var/at
    networks:
      $NETWORK_NAME:
        ipv4_address: $IP
NODE_EOF
done

cat >> "$WORK_DIR/docker-compose.yml" <<NET_EOF

networks:
  $NETWORK_NAME:
    driver: bridge
    ipam:
      config:
        - subnet: $SUBNET
NET_EOF

# ---------------------------------------------------------------
# Step 3: Start containers
# ---------------------------------------------------------------
info "Starting $NODE_COUNT containers ..."
docker compose -f "$WORK_DIR/docker-compose.yml" up -d

# ---------------------------------------------------------------
# Step 4: Wait for completion
# ---------------------------------------------------------------
info "Waiting up to ${TIMEOUT}s for test to complete ..."

ELAPSED=0
while [ $ELAPSED -lt $TIMEOUT ]; do
    RUNNING=$(docker compose -f "$WORK_DIR/docker-compose.yml" ps --status running -q 2>/dev/null | wc -l)
    if [ "$RUNNING" -eq 0 ]; then
        info "All containers exited after ${ELAPSED}s"
        break
    fi
    sleep 5
    ELAPSED=$((ELAPSED + 5))
done

if [ $ELAPSED -ge $TIMEOUT ]; then
    info "Timeout reached — collecting logs from running containers"
fi

# ---------------------------------------------------------------
# Step 5: Collect logs
# ---------------------------------------------------------------
for i in $(seq 1 $NODE_COUNT); do
    docker logs "at-fleet-node-$i" > "$WORK_DIR/node-$i.log" 2>&1 || true
done

# ---------------------------------------------------------------
# Step 6: Verify results
# ---------------------------------------------------------------
info "Verifying results ..."

# Node 1: proposal accepted
check "Node 1: proposal accepted" grep -q "accepted" "$WORK_DIR/node-1.log"

# Nodes 2-3: artifact download complete
for i in 2 3; do
    check "Node $i: artifact download complete" \
        grep -q "download complete" "$WORK_DIR/node-$i.log"
done

# Nodes 2-3: artifact store has complete marker
for i in 2 3; do
    check "Node $i: artifact store complete marker" \
        test -n "$(find "$WORK_DIR/node-$i/var/at/artifacts" -name "complete" 2>/dev/null)"
done

# ---------------------------------------------------------------
# Step 7: Report
# ---------------------------------------------------------------
echo
echo "=============================="
echo "  $PASSES passed, $FAILURES failed"
echo "=============================="

if [ $FAILURES -gt 0 ]; then
    info "Logs saved to $WORK_DIR/node-*.log"
    exit 1
fi
exit 0
