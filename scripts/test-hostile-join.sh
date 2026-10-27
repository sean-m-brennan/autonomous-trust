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
# test-hostile-join.sh — the hostile-join evaluation, live
# (RD_14.4_HOSTILE_JOIN_PLAN.md Phase 6, doc/architecture/hostile-join.md).
#
# Two honest joiners, verified contacts of each other, enter a cohort of N
# colluders that inflate each other, slander everyone else, and fail (or pass)
# AT's known-answer probes; with and without the join policy. Each run is a
# standalone compose the red-team harness brings up, lets run, reads the
# joiners' reputation dumps from, and brings down.
#
# Run from the repo root ON A HOST WITH DOCKER (not in the Claude sandbox).
# The image must carry the evaluation and first-contact packages:
#   scripts/build-docker.sh   (builds autonomous-trust-full-devel)
#
# Usage: scripts/test-hostile-join.sh [--sizes "4 8 16 32"] [--minutes 10]
#                                     [--image autonomous-trust-full-devel]
# ******************
set -uo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

SIZES="4 8 16 32"
MINUTES=10
IMAGE="autonomous-trust-full-devel"
while [ $# -gt 0 ]; do
  case "$1" in
    --sizes) SIZES="$2"; shift 2 ;;
    --minutes) MINUTES="$2"; shift 2 ;;
    --image) IMAGE="$2"; shift 2 ;;
    -h|--help) sed -n '18,33p' "$0"; exit 0 ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
done

OUT="$ROOT/.scale-results/hostile-join"
mkdir -p "$OUT"
export PYTHONPATH="$ROOT/src/autonomous-trust:$ROOT/src/autonomous-trust-evaluation:$ROOT/src/autonomous-trust-first-contact:${PYTHONPATH:-}"
export AUTONOMOUS_TRUST_BACKEND=python

for n in $SIZES; do
  for adversary in fail pass; do
    for policy in 0 1; do
      tag="n${n}-${adversary}-policy${policy}"
      echo "=== $tag (${MINUTES} min) ==="
      python3 - "$n" "$adversary" "$policy" "$MINUTES" "$IMAGE" "$OUT/$tag.json" <<'EOF' \
        || echo "run $tag FAILED"
import sys
from autonomous_trust.evaluation.redteam.harness import RedTeamHarness
from autonomous_trust.evaluation.redteam.colluding_cohort import ColludingCohortAttack
n, adversary, policy, minutes, image, out = sys.argv[1:7]
attack = ColludingCohortAttack(int(n), adversary, policy == '1', image=image)
harness = RedTeamHarness(baseline_path='', scenarios=[attack])
harness._load_baseline = lambda: {}
harness.run(out, quick=False, timeout_s=int(minutes) * 60 + 60)
EOF
    done
  done
done

python3 - "$OUT" <<'EOF'
import glob, json, os, sys
print('| colluders | adversary | policy | joiner | j2 trusted | colluders low | told tier, unprobed |')
print('|---|---|---|---|---|---|---|')
for path in sorted(glob.glob(os.path.join(sys.argv[1], 'n*.json'))):
    with open(path) as f:
        report = json.load(f)
    for scen in report.get('attacks', []):
        a = scen.get('attack_specific') or {}
        for j, r in (a.get('joiners') or {}).items():
            fmt = lambda v: '-' if v is None else '%.0f s' % v
            print('| %s | %s | %s | %s | %s | %s | %s |' % (
                a.get('colluders'), a.get('adversary'),
                'on' if a.get('policy') else 'off', j, fmt(r['t_honest']),
                fmt(r['t_colluders']) if a.get('adversary') == 'fail' else 'n/a',
                r['told_tier_unprobed']))
EOF
