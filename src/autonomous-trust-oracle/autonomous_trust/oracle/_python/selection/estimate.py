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
"""The off-policy estimator over the decision log (RD_12.7 plan §3.7, D8(b)).

Doubly robust (Dudik, Langford and Li 2011). For one decision over eligible
peers ``i`` with logged inclusion probability ``mu_i``, observed outcome
``r_i`` when the peer was selected and scored, and a reward model ``rhat_i``,
the value of a target policy ``pi`` is

    V(pi) = sum_i pi_i * (rhat_i + [observed_i / mu_i] * (r_i - rhat_i)) / sum_i pi_i

averaged over decisions. ``observed_i`` is 1 for a selected peer with a
numeric outcome, and 0 otherwise. A decline or a result still outstanding
contributes only the model term. The IPS correction keeps the estimate
unbiased when the model is wrong, and the model term keeps its variance down
when the model is right.

**The reward model is built from probe outcomes only.** The obvious model,
a peer's current reputation, is the very quantity the estimate checks, which
would make the correction circular (§2, D8). Probes have known answers, so
their outcomes say something about a peer that does not pass through
reputation. ``rhat`` for a peer is its mean probe outcome, shrunk toward the
mean over every probe by ``PRIOR_STRENGTH`` pseudo-observations, and is 0.5
when nothing has been probed. The model is the same for every capability, so
for an ordinary task it says only how this peer did on probes.

Three target policies are reported per capability: ``logged`` (the log's own
propensities), ``uniform`` (every eligible peer alike) and ``greedy`` (the
peer the model rates highest, lowest position on a tie). The regret of the
logged policy against each is the diagnostic D7(a) reports. Nothing here
enters reputation.

Pure and left to right for the C twin (``estimate.c``): decisions in index
order, peers in canonical position order.
"""

from __future__ import annotations

#: Pseudo-observations at the probe-wide mean behind each peer's own.
PRIOR_STRENGTH = 2.0

#: The model's value for a peer, and the prior mean, with no probe at all.
NEUTRAL = 0.5

POLICIES = ('logged', 'uniform', 'greedy')


def _numeric(outcome) -> bool:
    return isinstance(outcome, (int, float)) and not isinstance(outcome, bool)


def reward_model(records) -> tuple[dict[str, float], float]:
    """``({peer: rhat}, prior)`` from the probe decisions in ``records``: a
    peer the model has never seen is rated ``prior``."""
    sums: dict[str, float] = {}
    counts: dict[str, int] = {}
    order: list[str] = []
    total = 0.0
    n = 0
    for rec in records:
        if rec.get('purpose') != 'probe':
            continue
        for row in rec['eligible']:
            out = rec['outcome'].get(row['peer'])
            if not row['selected'] or not _numeric(out):
                continue
            if row['peer'] not in sums:
                sums[row['peer']] = 0.0
                counts[row['peer']] = 0
                order.append(row['peer'])
            sums[row['peer']] += float(out)
            counts[row['peer']] += 1
            total += float(out)
            n += 1
    prior = total / n if n else NEUTRAL
    return {peer: (sums[peer] + PRIOR_STRENGTH * prior) / (counts[peer] + PRIOR_STRENGTH)
            for peer in order}, prior


def _target(policy: str, rec: dict, rhat: list[float]) -> list[float]:
    if policy == 'logged':
        return [float(r['propensity']) for r in rec['eligible']]
    if policy == 'uniform':
        return [1.0] * len(rec['eligible'])
    best = 0
    for pos in range(1, len(rhat)):
        if rhat[pos] > rhat[best]:
            best = pos
    return [1.0 if pos == best else 0.0 for pos in range(len(rhat))]


def decision_value(policy: str, rec: dict, model: dict, prior: float) -> float:
    """One decision's doubly robust value under ``policy``."""
    rows = rec['eligible']
    rhat = [model.get(r['peer'], prior) for r in rows]
    pis = _target(policy, rec, rhat)
    num = 0.0
    den = 0.0
    for pos, row in enumerate(rows):
        term = rhat[pos]
        out = rec['outcome'].get(row['peer'])
        mu = float(row['propensity'])
        if row['selected'] and _numeric(out) and mu > 0.0:
            term += (float(out) - rhat[pos]) / mu
        num += pis[pos] * term
        den += pis[pos]
    return num / den if den > 0.0 else 0.0


def estimate(records) -> dict:
    """``{capability: {decisions, observed, value: {...}, regret: {...}}}``
    over the decisions in ``records`` (in index order) that have at least
    one observed outcome."""
    records = sorted(records, key=lambda rec: int(rec['index']))
    model, prior = reward_model(records)
    out: dict[str, dict] = {}
    for rec in records:
        observed = 0
        for row in rec['eligible']:
            if row['selected'] and _numeric(rec['outcome'].get(row['peer'])):
                observed += 1
        if observed == 0:
            continue
        entry = out.setdefault(rec['capability'], {
            'decisions': 0, 'observed': 0,
            'value': {p: 0.0 for p in POLICIES}})
        entry['decisions'] += 1
        entry['observed'] += observed
        for policy in POLICIES:
            entry['value'][policy] += decision_value(policy, rec, model, prior)
    for entry in out.values():
        for policy in POLICIES:
            entry['value'][policy] /= entry['decisions']
        logged = entry['value']['logged']
        entry['regret'] = {'uniform': entry['value']['uniform'] - logged,
                           'greedy': entry['value']['greedy'] - logged}
    return out
