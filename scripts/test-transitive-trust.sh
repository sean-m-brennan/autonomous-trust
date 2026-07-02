#!/bin/bash
# ******************
# test-transitive-trust.sh — verify the transitive (peer-of-peer) trust
# rendering work (§4 inspector, Stages 1-5).
#
# Run from the repo root ON THE HOST (the browser gates need a display + the
# demo stack; do NOT run the docker demos in the Claude sandbox).
# ******************
set -uo pipefail
# Script lives in scripts/; the repo root is one level up.
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

echo "=================================================================="
echo " GATE A — automated: server-side pipeline (no browser needed)"
echo "=================================================================="
# Proves Stages 1-3: run_data_handlers graph-folding (incl. transitive edge
# trust + trust_level scalar), the shared peer-pair query mixin, and the daq
# per-other reputation capture. Requires: networkx, aenum (pip install if absent).
cd "$ROOT/src/autonomous-trust-inspector" || exit 1
AUTONOMOUS_TRUST_BACKEND=python python -m pytest \
    tests/a_unit/test_live_graph.py \
    tests/a_unit/test_transitive_trust.py \
    tests/a_unit/test_daq.py \
    -v || { echo "GATE A FAILED"; exit 1; }
echo "GATE A passed: server-side transitive-trust pipeline is correct."
echo

echo "=================================================================="
echo " GATE B — browser: stock inspector live graph (Stage 4)"
echo "=================================================================="
cat <<'EOF'
The stock inspector's live network graph (viz/js/force.js) now colors:
  * EDGES  by transitive trust_level  (red=distrust .. amber .. green=trust)
  * NODES  by a reputation ring       (same red->green ramp; white if unknown)

To see it, launch an inspector/evaluation run that drives the live graph and
open the viz page in a browser. Peer-pair reputation queries fire every
PEER_PAIR_QUERY_SEC (60s), so allow ~1-2 minutes for transitive edges to color.

WHAT TO LOOK FOR:
  * Initially uncolored/group-colored edges.
  * After the first peer-pair round, edges between peers gain red/amber/green
    color reflecting the worst-case bilateral trust; node rings reflect each
    peer's direct reputation.
  * A peer whose reputation drops should shift its ring/edges toward red.
EOF
echo

echo "=================================================================="
echo " GATE C — browser: multi_agency demo (already renders trust)"
echo "=================================================================="
cat <<'EOF'
The multi_agency demo ALREADY renders transitive trust (rep_pair ->
_live_trust_matrix -> Trust Network graph). Use it to confirm the end-to-end
flow independent of the stock inspector:

    cd examples/multi_agency/deploy && ./run-demo.sh          # live
    # or a recorded run:
    cd examples/multi_agency/deploy && ./run-demo.sh --playback <file>

Open the dashboard, select the "Trust Network" panel, and watch bilateral
trust edges appear/recolor as peers exchange reputation.
EOF
echo

echo "=================================================================="
echo " GATE D — browser: DoD mission demo (Stage 5 — SEE NOTE)"
echo "=================================================================="
cat <<'EOF'
    cd examples/dod_mission/deploy && ./run-demo.sh [--playback <file>]

Stage 5 is now wired end-to-end:
  * Coordinator (DoDMissionCoordinator) mixes in TransitiveTrustMixin and runs a
    peer-pair reputation query round (~every PEER_PAIR_QUERY_SEC); replies land
    in latest_reputation_pairs. _build_trust_matrix() min-combines the two
    directional views per pair (skepticism-wins), resolves uuids to roster
    names, and publishes it in dashboard state as `trust_matrix`.
  * The new "Trust Network" chart panel (dashboard/trust_network_panel.py,
    keyed "trust_network") renders it via build_graph_from_scenario.

WHAT TO LOOK FOR: a Trust Network graph in the chart column. Initially just the
roster (no trust edges); after the first peer-pair round (~1 min), colored
bilateral edges appear between peers (red=distrust .. green=trust), and a
compromised peer's edges shift red as its neighbors' opinions sour.
EOF
