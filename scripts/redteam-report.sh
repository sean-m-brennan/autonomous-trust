#!/bin/bash
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
# Run the behavioural-anomaly resilience/threat M&S red-team suite (SOW Task 3.4)
# and print two tables -- the headline "case for a governed sensor" (as in
# last.md) and the full aggregate detector metrics -- each with a direction
# column ("↑/↓ better" + acceptance target) and a PASS/FAIL column judging the
# ML governed sensor against that target.
#
# Usage:
#   scripts/redteam-report.sh                 # the two tables (default seed 1234)
#   scripts/redteam-report.sh --seed 7        # different deterministic seed
#   scripts/redteam-report.sh --json out.json # also write the full JSON report
#
# Acceptance targets are inline in the table() rows below -- edit to taste.
# Deterministic: a fixed seed reproduces byte-identical metrics.
set -euo pipefail

SEED=1234
JSON=""
while [ $# -gt 0 ]; do
    case "$1" in
        --seed) SEED="$2"; shift 2 ;;
        --json) JSON="$2"; shift 2 ;;
        -h|--help) sed -n '18,29p' "$0"; exit 0 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

# Repo root = parent of this script's dir.
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BEHAVIOUR="$ROOT/src/autonomous-trust-behaviour"

# The redteam suite drives the pure library, which needs river/pyod. Project
# deps are managed via conda (env "autonomous_trust"); a repo-local .venv is a
# secondary location. Pick the first interpreter that can actually import river
# -- preferring the active env (conda/venv on PATH), then $CONDA_PREFIX, then the
# repo .venv -- so the script works whether you run it inside the conda env or
# bare.
PY=""
for cand in \
    "$(command -v python3 || true)" \
    "$(command -v python || true)" \
    "${CONDA_PREFIX:+$CONDA_PREFIX/bin/python}" \
    "$ROOT/src/autonomous-trust/.venv/bin/python"; do
    [ -n "$cand" ] && [ -x "$cand" ] || continue
    if "$cand" -c 'import river, pyod' >/dev/null 2>&1; then
        PY="$cand"
        break
    fi
done
if [ -z "$PY" ]; then
    echo "error: no python with river+pyod found." >&2
    echo "  Activate the conda env first:  conda activate autonomous_trust" >&2
    echo "  (deps: river, pyod -- see config/cfg/environment.yml)" >&2
    exit 1
fi

export PYTHONPATH="$BEHAVIOUR${PYTHONPATH:+:$PYTHONPATH}"
export AUTONOMOUS_TRUST_BACKEND=python

REDTEAM_SEED="$SEED" REDTEAM_JSON="$JSON" "$PY" - <<'PY'
import json
import os

from autonomous_trust.behaviour.redteam.harness import RedTeamConfig, run
from autonomous_trust.behaviour.redteam.archetypes import (
    COMPROMISED_CREDENTIAL, DDIL)

seed = int(os.environ.get('REDTEAM_SEED', '1234'))
result = run(RedTeamConfig(seed=seed))
m, b = result.ml, result.baseline


def cell(v, places=2):
    return f'{v:.{places}f}' if v is not None else '—'


def better(direction, target, places=2):
    """The direction column: arrow + comparator + acceptance target."""
    if direction is None:
        return '—'
    arrow, cmp_ = ('↑', '≥') if direction == 'up' else ('↓', '≤')
    return f'{arrow} {cmp_} {target:.{places}f}'


def verdict(val, direction, target):
    """PASS/FAIL of the ML governed sensor's value against its target."""
    if val is None or direction is None or target is None:
        return '—'
    ok = (val >= target) if direction == 'up' else (val <= target)
    return 'PASS' if ok else 'FAIL'


def emit(headers, rows):
    """Render a markdown table from string headers + string rows."""
    widths = [len(h) for h in headers]
    for r in rows:
        for i, c in enumerate(r):
            widths[i] = max(widths[i], len(c))

    def line(cols):
        return ('| ' + ' | '.join(c.ljust(widths[i]) for i, c in enumerate(cols))
                + ' |')
    print(line(headers))
    print('|' + '|'.join('-' * (w + 2) for w in widths) + '|')
    for r in rows:
        print(line(r))


def table(headers, specs):
    """specs row = (name, ml_val, ml_display, bl_display, direction, target,
    places). Renders Metric | Better/target | ML governed | baseline | Result."""
    emit(headers, [
        [name, better(direction, target, places), ml_disp, bl_disp,
         verdict(ml_val, direction, target)]
        for name, ml_val, ml_disp, bl_disp, direction, target, places in specs])


HEADERS = ['Metric', 'Better / target', 'ML governed sensor',
           'Static baseline', 'Result']

print('# Behavioural-anomaly red-team M&S (SOW Task 3.4)')
print()
print(f'Population: {result.population} peers · seed {seed} '
      '(deterministic — a fixed seed reproduces byte-identical metrics).')
print()
print('_Result = the ML governed sensor judged against the per-metric '
      'acceptance target_')
print('_(the “Better / target” column); these targets are editable in '
      'redteam-report.sh._')
print()

comp_ml = m.archetype_detection_rate(COMPROMISED_CREDENTIAL)
comp_bl = b.archetype_detection_rate(COMPROMISED_CREDENTIAL)
ddil_ml = m.archetype_detection_rate(DDIL)
ddil_bl = b.archetype_detection_rate(DDIL)
ddil_bl_disp = (cell(ddil_bl) + ' (all)') if (ddil_bl or 0) >= 1.0 else cell(ddil_bl)

# -- A. Headline (the last.md table) ----------------------------------------
print('## Headline — the case for a governed sensor')
print()
table(HEADERS, [
    ('Compromised-credential detection', comp_ml, cell(comp_ml), cell(comp_bl),
     'up', 0.90, 2),
    ('False-exclusion rate (FPR)', m.fpr, cell(m.fpr), cell(b.fpr),
     'down', 0.05, 2),
    ('DDIL false-exclusion', ddil_ml, cell(ddil_ml), ddil_bl_disp,
     'down', 0.05, 2),
    ('Precision @ base-rate 0.01', m.ppv_at_base_rate(0.01),
     cell(m.ppv_at_base_rate(0.01)), cell(b.ppv_at_base_rate(0.01)),
     'up', 0.50, 2),
    ('Detection latency (mean)', m.latency_mean,
     cell(m.latency_mean, 1), cell(b.latency_mean, 1), 'down', 25.0, 1),
])
print()

# -- B. Full aggregate metrics ----------------------------------------------
print('## Aggregate detector metrics (all peers)')
print()
table(HEADERS, [
    ('Detection rate (TPR)', m.tpr, cell(m.tpr), cell(b.tpr), 'up', 0.50, 2),
    ('False-exclusion rate (FPR)', m.fpr, cell(m.fpr), cell(b.fpr),
     'down', 0.05, 2),
    ('Precision @ observed mix', m.ppv, cell(m.ppv), cell(b.ppv), 'up', 0.50, 2),
    ('Precision @ base-rate 0.10', m.ppv_at_base_rate(0.10),
     cell(m.ppv_at_base_rate(0.10)), cell(b.ppv_at_base_rate(0.10)),
     'up', 0.50, 2),
    ('Precision @ base-rate 0.05', m.ppv_at_base_rate(0.05),
     cell(m.ppv_at_base_rate(0.05)), cell(b.ppv_at_base_rate(0.05)),
     'up', 0.50, 2),
    ('Precision @ base-rate 0.01', m.ppv_at_base_rate(0.01),
     cell(m.ppv_at_base_rate(0.01)), cell(b.ppv_at_base_rate(0.01)),
     'up', 0.50, 2),
    ('Detection latency (mean)', m.latency_mean,
     cell(m.latency_mean, 1), cell(b.latency_mean, 1), 'down', 25.0, 1),
    ('Detection latency (median)', m.latency_median,
     cell(m.latency_median, 1), cell(b.latency_median, 1), 'down', 25.0, 1),
])
print()

# -- C. Confusion matrix (raw counts the rates are built from) --------------
print('## Confusion matrix (counts)')
print()
print('_Positive = the detector flagged a peer (would propose exclusion); '
      'ground truth = whether the peer is truly an adversary._')
print()
emit(['Outcome', 'Meaning', 'ML governed sensor', 'Static baseline'], [
    ['TP — true positive', 'adversary correctly flagged', str(m.tp), str(b.tp)],
    ['FP — false positive', 'innocent peer wrongly excluded', str(m.fp), str(b.fp)],
    ['FN — false negative', 'attacker missed', str(m.fn), str(b.fn)],
    ['TN — true negative', 'innocent peer correctly left alone', str(m.tn), str(b.tn)],
])

json_path = os.environ.get('REDTEAM_JSON') or ''
if json_path:
    with open(json_path, 'w') as fh:
        json.dump(result.as_report(), fh, indent=2)
    print(f'\n[wrote JSON report to {json_path}]')
PY
