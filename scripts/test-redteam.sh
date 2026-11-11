#!/bin/bash
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
# test-redteam.sh — the live red-team attacks (doc/architecture/adversarial-testing.md)
#
# Each run is a standalone compose the red-team harness brings up, lets run,
# reads the nodes' logs (and the MITM sidecar's capture) from, and brings
# down. Arms:
#   sybil-k3, sybil-k6     3 or 6 Sybils join 120 s after the honest cohort
#   byzantine              one equivocating member
#   gaming-tenure0/1       a gamer defects at 480 s; honest nodes without and
#                          with a 300 s minimum tenure
#   mitm                   capture 600 s from honest-1's namespace, replay at 660 s
# Every arm runs with six honest nodes, each one repeated. Reports and every
# node's log go to .scale-results/redteam-<arm>/<repeat>/.
#
# Run from the repo root ON A HOST WITH DOCKER (not in the Claude sandbox).
# The image must carry the evaluation, first-contact and rendezvous packages:
#   scripts/build-docker.sh full-devel
#
# Usage: scripts/test-redteam.sh [--arms "sybil-k3 ... mitm"] [--repeats 3]
#                                [--minutes 20] [--honest 6]
#                                [--image autonomous-trust-full-devel]
# ******************
set -uo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

ARMS="sybil-k3 sybil-k6 byzantine gaming-tenure0 gaming-tenure1 mitm"
REPEATS=3
MINUTES=20
HONEST=6
IMAGE="autonomous-trust-full-devel"
while [ $# -gt 0 ]; do
  case "$1" in
    --arms) ARMS="$2"; shift 2 ;;
    --repeats) REPEATS="$2"; shift 2 ;;
    --minutes) MINUTES="$2"; shift 2 ;;
    --honest) HONEST="$2"; shift 2 ;;
    --image) IMAGE="$2"; shift 2 ;;
    -h|--help) sed -n '18,38p' "$0"; exit 0 ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
done

export PYTHONPATH="$ROOT/src/autonomous-trust:$ROOT/src/autonomous-trust-evaluation:$ROOT/src/autonomous-trust-first-contact:$ROOT/src/autonomous-trust-rendezvous:${PYTHONPATH:-}"
export AUTONOMOUS_TRUST_BACKEND=python

RUNS=()
for arm in $ARMS; do
  for rep in $(seq 1 "$REPEATS"); do
    out="$ROOT/.scale-results/redteam-$arm/$rep"
    # A rerun replaces the old one: no stale logs or report beside the new.
    rm -rf "$out"
    mkdir -p "$out"
    RUNS+=("$out")
    echo "=== $arm #$rep (${MINUTES} min) $(date -Is) ==="
    python3 - "$arm" "$HONEST" "$MINUTES" "$IMAGE" "$out" <<'EOF' \
      || echo "run $arm #$rep FAILED"
import os, sys
from autonomous_trust.evaluation.redteam.harness import RedTeamHarness
arm, honest, minutes, image, out = sys.argv[1:6]
honest, minutes = int(honest), int(minutes)
if arm.startswith('sybil-k'):
    from autonomous_trust.evaluation.redteam.sybil_attack import SybilAttack
    attack = SybilAttack(int(arm[len('sybil-k'):]), honest, image=image)
elif arm == 'byzantine':
    from autonomous_trust.evaluation.redteam.byzantine_node import ByzantineNodeAttack
    attack = ByzantineNodeAttack(1, honest, image=image)
elif arm.startswith('gaming-tenure'):
    from autonomous_trust.evaluation.redteam.reputation_gaming import ReputationGamingAttack
    attack = ReputationGamingAttack(1, honest, image=image,
                                    tenure_s=300 if arm.endswith('1') else 0)
elif arm == 'mitm':
    from autonomous_trust.evaluation.redteam.mitm_attack import MitmAttack
    attack = MitmAttack(honest, image=image)
else:
    sys.exit('unknown arm %s' % arm)

# Keep every container's log beside the report, for diagnosis.
setup, collect = attack.setup, attack.collect
def keep_setup(sim, comp):
    setup(sim, comp)
    sim['collect_logs'] = sorted(set(sim['collect_logs']) | set(comp['services']))
def keep_collect(metrics):
    for name, text in (metrics.get('logs') or {}).items():
        with open(os.path.join(out, name + '.log'), 'w') as f:
            f.write(text)
    for name, text in (metrics.get('artifacts') or {}).items():
        with open(os.path.join(out, name), 'w') as f:
            f.write(text)
    return collect(metrics)
attack.setup, attack.collect = keep_setup, keep_collect
h = RedTeamHarness(baseline_path='', scenarios=[attack])
h._load_baseline = lambda: {}
# The standalone run lasts timeout_s - 60 seconds.
h.run(os.path.join(out, 'report.json'), quick=False,
      timeout_s=minutes * 60 + 60)
EOF
  done
done

# The summary covers this invocation's runs only.
python3 - "${RUNS[@]}" <<'EOF'
import json, os, sys
print('| arm | repeat | result | key figures | failed checks |')
print('|---|---|---|---|---|')
for path in (os.path.join(d, 'report.json') for d in sys.argv[1:]):
    if not os.path.exists(path):
        print('| %s | %s | NO_REPORT | | |' % tuple(path.split(os.sep)[-3:-1]))
        continue
    arm = path.split(os.sep)[-3][len('redteam-'):]
    rep = path.split(os.sep)[-2]
    with open(path) as f:
        report = json.load(f)
    for scen in report.get('attacks', []):
        a = scen.get('attack_specific') or {}
        keys = ('admitted_max', 'sybils_seen_max', 'equivocations_logged',
                'byz_commits_max', 'frames', 'opaque', 'replayed', 'refusals')
        figs = ', '.join('%s=%s' % (k, a[k]) for k in keys if k in a)
        print('| %s | %s | %s | %s | %s |' % (
            arm, rep, scen.get('result'), figs,
            '; '.join(a.get('failed_checks') or []) or '-'))
EOF
