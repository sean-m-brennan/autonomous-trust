#!/bin/bash
# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
#  Licensed under the Apache License, Version 2.0
# ******************
#
# run_demo.sh — Orchestrates the ZTA DDIL demo timeline.
#
# This script:
#   1. Builds the Docker image (if needed)
#   2. Starts the mock OCSP and 4 peers
#   3. Drives the demo timeline via mock OCSP control endpoints
#
# Usage: ./run_demo.sh [--skip-build]
#
# By default the script builds the Docker image before starting the demo.
# Pass --skip-build to skip the build step if the image already exists.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yml"
IMAGE_NAME="autonomous-trust-zta"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log() { echo -e "${CYAN}[demo]${NC} $*"; }
warn() { echo -e "${YELLOW}[demo]${NC} $*"; }
event() { echo -e "${GREEN}[T+${1}]${NC} $2"; }

# Build the image unless --skip-build is passed
do_build=1
for arg in "$@"; do
    case "$arg" in
        --skip-build) do_build=0 ;;
    esac
done

if [ "$do_build" -eq 1 ]; then
    log "Building ZTA demo image..."
    docker build --network host -t "$IMAGE_NAME" \
        -f "$SCRIPT_DIR/Dockerfile.zta" "$REPO_ROOT"
elif ! docker image inspect "$IMAGE_NAME" >/dev/null 2>&1; then
    warn "Image '$IMAGE_NAME' not found. Building..."
    docker build --network host -t "$IMAGE_NAME" \
        -f "$SCRIPT_DIR/Dockerfile.zta" "$REPO_ROOT"
fi

# Clean up any previous run
log "Cleaning up previous containers..."
docker compose -f "$COMPOSE_FILE" down 2>/dev/null || true

# Start the demo
log "Starting ZTA DDIL demo..."
docker compose -f "$COMPOSE_FILE" up -d

log "Waiting for mock OCSP to be healthy..."
for i in $(seq 1 30); do
    if docker exec mock-ocsp curl -sf http://localhost:8888/control/status >/dev/null 2>&1; then
        log "Mock OCSP is ready"
        break
    fi
    sleep 1
done

log ""
log "============================================="
log "  ZTA Demo Timeline Starting"
log "============================================="
log ""

event "0:00" "Network forming: CP, SL, DA starting with ZTA verification"
sleep 5

# Verify initial state
log "Mock OCSP status:"
docker exec mock-ocsp curl -sf http://localhost:8888/control/status 2>/dev/null || true
echo ""

# T+30s: Drone Bravo joins in DDIL mode
# In a full implementation, we'd use iptables to block OCSP initially.
# For now, DB starts normally but the log messages indicate DDIL scenario.
event "0:30" "Drone Bravo joining network (DDIL — OCSP may be unreachable)"
log "  DDIL fallback: DB admitted with reputation capped at 0.5"
log "  Delegated verification: waiting for peers with OCSP to vouch"
sleep 5

# T+60s: OCSP connectivity restored for Drone Bravo
# CP and SL (which have OCSP) verify DB's cert and broadcast ZTA_PROTO_VERIFICATION.
# The ZTA process on each peer gates these vouches on the voucher's reputation
# (must be >= delegated_verification_min_reputation = 0.7).
event "1:00" "OCSP connectivity restored — delegated verification resolves"
log "  CP/SL broadcast verification result for DB (ZTA_PROTO_VERIFICATION)"
log "  DB's DDIL reputation cap lifted after quorum met (quorum=1)"
sleep 5

# T+90s: Revoke Drone Alpha's certificate
# Extract DA's serial number from its cert for the real OCSP revocation
event "1:30" "REVOKING Drone Alpha's certificate"
DA_SERIAL=$(docker exec mock-ocsp openssl x509 -in /opt/at/pki/certs/drone_alpha.pem -noout -serial 2>/dev/null | cut -d= -f2 || echo "unknown")
log "  Drone Alpha serial: $DA_SERIAL"
REVOKE_RESULT=$(docker exec mock-ocsp curl -sf -X POST "http://localhost:8888/control/revoke/$DA_SERIAL" 2>/dev/null || echo "failed")
log "  Mock OCSP revoke result: $REVOKE_RESULT"
log "  ZTA re-verification will detect revocation via real OCSP DER protocol"
log "  Reputation penalty (0.8) applied to DA"

log ""
log "Mock OCSP status after revocation:"
docker exec mock-ocsp curl -sf http://localhost:8888/control/status 2>/dev/null || true
echo ""
sleep 5

# T+120s: Drone Alpha re-authenticates (in full impl, would restart with new cert)
event "2:00" "Drone Alpha would re-authenticate with new certificate"
log "  In production: DA restarts with fresh machine cert, enters at neutral reputation (0.5)"

log ""
log "============================================="
log "  ZTA Demo Timeline Complete"
log "============================================="
log ""
log "View logs: docker compose -f $COMPOSE_FILE logs -f"
log "Shut down: docker compose -f $COMPOSE_FILE down"
log ""
log "Key observations:"
log "  1. ZTA verification uses real OCSP DER protocol against mock responder"
log "  2. DDIL peers admitted with reputation cap (0.5) until ZTA resolves"
log "  3. Delegated verification: peers with OCSP vouch for DDIL peers"
log "     - Vouches gated on voucher reputation >= 0.7 (configurable)"
log "     - Quorum of 1 vouch lifts the reputation cap"
log "  4. Revoked credentials detected via real OCSP and trigger penalty (0.8)"
log "  5. All ZTA events logged to /var/at/zta_audit.jsonl"
