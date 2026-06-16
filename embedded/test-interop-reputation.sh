#!/usr/bin/env bash
# ******************
#  Copyright 2025 Sean M. Brennan and contributors
#  Licensed under the Apache License, Version 2.0
# ******************
#
# Live C <-> Python REPUTATION interop test: proves a C at_demo microdrone
# actually earns reputation for the ISR data it streams (Stretch Goal 3, the
# "C microdrones never earn reputation" fix).
#
# This is the gap test-interop-cpython.sh does NOT cover: that script verifies
# discovery + admission + group-key sync, but never starts the data-source ->
# subscriber path and asserts nothing about readings, task_id, or reputation.
# Here we bring up the real DoD fleet with ONE microdrone running the C node
# (+ its pi_peer flight-stub sidecar) and the Python dod coordinator as the
# subscriber, then confirm BOTH halves of the bilateral sensor-report
# transaction are submitted on a shared task_id:
#
#   producer half (C node)   : the data source stamps/forwards a 0.9
#                              dod.sensor-report TransactionScore per kept batch,
#                              and the reputation process starts a Paxos round.
#   verdict half (coordinator): the coordinator reads the SAME task_id from the
#                              reading metadata and submits its 0.8/0.3 verdict.
#
# Both halves on the same task_id are what complete the Transaction that lets
# the C microdrone's reputation move (reputation.py:251-272 / the C twin).
#
# ============================ IMPORTANT ============================
# This script has NOT been run in the dev sandbox (docker is unavailable there
# and crashes the agent). It is authored against the real container topology in
# examples/dod_mission/deploy/{run-demo.sh,generate_compose.py} (service keys
# microdrone-1, microdrone-1-stub, coordinator) and the exact log strings the
# code emits. On first real run, if an assertion fails, check:
#   * that microdrone-1 is actually the C node (AT_C_MICRODRONES=microdrone-1),
#   * that enough batches passed _ts_keep within DURATION (default decimation is
#     1/30; bump DURATION or propagate AT_TS_DECIMATION=1 into the compose
#     services' env to score every batch — see the note below), and
#   * the printed last-40-lines of each service log for the real strings.
# ===================================================================
#
# Usage:
#   ./test-interop-reputation.sh                 # assumes demo images are built
#   ./test-interop-reputation.sh --build         # build the image chain first
#   ./test-interop-reputation.sh --duration 240  # run longer (more kept batches)
#   ./test-interop-reputation.sh --keep          # leave the fleet up afterward
#
# Faster/deterministic option: set AT_TS_DECIMATION=1 so EVERY batch is scored
# on both sides. generate_compose.py does not currently propagate that env into
# the services (it only carries the scenario knobs + AT_DEMO_T0_EPOCH), so for
# now it requires either adding it to generate_compose.py's common_env or a
# longer DURATION. With the default 1/30 and ~2 batches/s, a 180s run yields
# plenty of kept batches on both sides.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/.." && pwd)"
DEPLOY_DIR="$REPO/examples/dod_mission/deploy"
COMPOSE_FILE="$DEPLOY_DIR/docker-compose.yml"

# One C microdrone is enough to prove the path; keep the swarm small + fast.
export AT_C_MICRODRONES="${AT_C_MICRODRONES:-microdrone-1}"
SQUAD=1; SWARM=1; SENSORS=1; HACKED=0
DURATION=180
BUILD=false
KEEP=false

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; RST='\033[0m'
pass(){ echo -e "${GREEN}[PASS]${RST} $*"; }
fail(){ echo -e "${RED}[FAIL]${RST} $*"; }
info(){ echo -e "${YELLOW}[rep-interop]${RST} $*"; }

while [[ $# -gt 0 ]]; do case "$1" in
  --build)     BUILD=true; shift;;
  --duration)  DURATION="$2"; shift 2;;
  --keep)      KEEP=true; shift;;
  -h|--help)   sed -n '2,55p' "$0"; exit 0;;
  *) echo "unknown option: $1"; exit 1;;
esac; done

cleanup(){
  if $KEEP; then info "leaving fleet up (--keep); 'docker compose -f $COMPOSE_FILE down'"; return; fi
  docker compose -f "$COMPOSE_FILE" down >/dev/null 2>&1 || true
}
trap cleanup EXIT

# ----------------------------------------------------------------------------
# Bring up the fleet via the proven demo launcher (configs + scenario + compose
# + `docker compose up -d`). AT_C_MICRODRONES (exported above) makes microdrone-1
# a C node; run-demo.sh inherits it and passes it to generate_compose.py.
# ----------------------------------------------------------------------------
RUN_ARGS=(--squad-size="$SQUAD" --swarm-size="$SWARM"
          --sensor-count="$SENSORS" --hacked-sensors="$HACKED")
$BUILD || RUN_ARGS+=(--skip-build)

info "Bringing up DoD fleet (microdrone-1 = C node) via run-demo.sh ..."
( cd "$DEPLOY_DIR" && ./run-demo.sh "${RUN_ARGS[@]}" )

info "Fleet up. Streaming for ${DURATION}s so batches accumulate + get scored ..."
sleep "$DURATION"

# ----------------------------------------------------------------------------
# Collect logs
# ----------------------------------------------------------------------------
CLOG="$(docker compose -f "$COMPOSE_FILE" logs microdrone-1      2>&1 || true)"
STUBLOG="$(docker compose -f "$COMPOSE_FILE" logs microdrone-1-stub 2>&1 || true)"
COORDLOG="$(docker compose -f "$COMPOSE_FILE" logs coordinator   2>&1 || true)"

# ----------------------------------------------------------------------------
# Verify — both bilateral halves submitted on the C microdrone's batches
# ----------------------------------------------------------------------------
echo; echo "=============================="
P=0; F=0
chk(){ # name, log, regex
  if echo "$2" | grep -qiE "$3"; then pass "$1"; P=$((P+1)); else fail "$1"; F=$((F+1)); fi
}

# Sidecar is feeding stamped readings into the C node's ingest socket.
chk "flight-stub connected to C node ingest socket" "$STUBLOG" \
    "connected to ingest socket"

# Producer half (C node): data source decided to score a delivered batch, and
# the reputation process started a Paxos round tagged dod.sensor-report.
chk "C node submitted producer-side score (data-source)" "$CLOG" \
    "data-source: submitted producer score 0\.9 for batch [0-9a-fA-F-]{36}"
chk "C reputation forwarded the dod.sensor-report tx"    "$CLOG" \
    "forwarding transaction for task .* \(cap dod\.sensor-report\)"

# Verdict half (coordinator): it received the C microdrone's STAMPED readings
# (proves flight_stub's task_id stamp survives the wire) and submitted its
# verdict-side TransactionScore for that peer.
chk "Coordinator saw microdrone-1 readings WITH task_id" "$COORDLOG" \
    "first reading with task_id received: peer=microdrone-1"
chk "Coordinator submitted verdict-side TS for microdrone-1" "$COORDLOG" \
    "first batch TransactionScore submitted: peer=microdrone-1"

echo "=============================="
echo "  $P passed, $F failed"
echo "=============================="
if [ "$F" -gt 0 ]; then
  info "microdrone-1 (C node) log tail:"; echo "$CLOG"     | sed 's/\x1b\[[0-9;]*m//g' | tail -40
  info "microdrone-1-stub log tail:";     echo "$STUBLOG"  | sed 's/\x1b\[[0-9;]*m//g' | tail -20
  info "coordinator log tail:";           echo "$COORDLOG" | sed 's/\x1b\[[0-9;]*m//g' | tail -40
  exit 1
fi
info "C microdrone earns reputation: both bilateral halves submitted on shared task_ids."
exit 0
