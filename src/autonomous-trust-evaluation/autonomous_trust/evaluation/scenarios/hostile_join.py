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
"""Two honest nodes joining a colluding cohort, with and without the join
policy (RD_14.4_HOSTILE_JOIN_PLAN.md Phase 6).

A deterministic in-process simulation. One honest joiner (``j1``) runs a real
Python ``ReputationProcess`` and is scored exactly as a node is; the cohort
(N colluders) and the second honest joiner (``j2``, a verified contact of
j1's) exist as the evidence they leave on j1's chain:

- **Told evidence.** Before j1 arrives the colluders have written entries
  inflating each other and slandering j2, and j1 adopts them by catch-up
  (marked told under the policy, Phase 3).
- **Probes.** j1 probes. Without the policy it probes continuously, one
  probe per ``probe_interval`` (60 s), round-robin over its peers, as UCB does
  cold. With it the join burst runs first (Phase 5): ``burst_k`` probes per
  peer read under the told ceiling, one per ``burst_interval`` (5 s), then the
  continuous probing. A colluder either fails every probe (``fail``) or
  passes it (``pass``, the careful adversary); j2 passes.
- **Work.** j1 and j2 transact (``task_interval``, 60 s), well on both sides.
  Under the policy they hold an anchored cohort (Phase 6) and the entries go
  to its chain; the scorers read it beside the primary.
- **The seed.** j2 is a verified contact, so first contact seeds it; under the
  policy the seed beats a told-only score (Phase 4).

Verdicts and task scores land the moment they are issued: the simulation
measures the protocol's decisions, not the network's latency, and the
bootstrap window's fan-out pairs are left out of both arms alike.

Observables, per run:

- ``t_honest``: seconds until j1 holds j2 at tier >= HONEST_TIER, or None.
- ``t_colluders``: seconds until every colluder is below tier 1 (only for the
  ``fail`` adversary, where that is the correct reading), or None.
- ``told_tier_unprobed``: the highest tier j1 gave a colluder it had no
  evidence of its own about: what the cohort's word alone bought.

``sweep()`` runs every combination of cohort size (4, 8, 16, 32), adversary
and policy. Run as a module for the table:
``python -m autonomous_trust.evaluation.scenarios.hostile_join``.
"""

from __future__ import annotations

import logging
import os
import queue
import tempfile
from dataclasses import dataclass
from types import SimpleNamespace
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

#: The tier an honest peer is correctly held at (trusted for replication).
HONEST_TIER = 3
#: Score a colluder gives another colluder, and gives j2 (told evidence).
INFLATE, SLANDER = 0.95, 0.1
#: Verdicts: a passed and a failed known-answer probe.
PASS, FAIL = 0.9, 0.1
#: j1's and j2's scores of each other's work.
GOOD_WORK = 0.9
#: Entries each colluder pair wrote, and about j2, before j1 arrived.
TOLD_ROUNDS = 3

_NS = uuid5(NAMESPACE_URL, 'https://autonomous-trust/evaluation/hostile-join')


@dataclass
class Result:
    colluders: int
    adversary: str
    policy: bool
    t_honest: float | None
    t_colluders: float | None
    told_tier_unprobed: int


def _process(policy_on: bool, me: UUID, peers: list):
    """A real ReputationProcess for j1, built with the minimum it needs."""
    from autonomous_trust.core import CfgIds
    from autonomous_trust.core._python.processes import ProcessTracker
    from autonomous_trust.core._python.reputation.repprocess import ReputationProcess
    from autonomous_trust.core._python.identity.join_policy import JoinPolicy

    procs = [SimpleNamespace(name=n) for n in (
        CfgIds.network, CfgIds.identity, CfgIds.negotiation, CfgIds.reputation)]
    configs = {
        'processes': procs,
        CfgIds.identity: SimpleNamespace(uuid=me, nickname='j1', address='10.0.0.1'),
        CfgIds.peers: SimpleNamespace(all=peers),
        CfgIds.group: None,
    }
    rp = ReputationProcess(configs, ProcessTracker(), queue.Queue(),
                           suppress_log=True)
    rp.join_policy = (JoinPolicy(enabled=True, anchors=frozenset({'verified_contact'}))
                      if policy_on else JoinPolicy())
    rp._warm_started = set()
    rp.protocol.peers = SimpleNamespace(all=peers)
    return rp


def _pair(chain, task, a, a_score, b, b_score, a_channel=None):
    chain.update(task, a, a_score, a_channel)
    chain.update(task, b, b_score)


def _tier_of(rp, peer):
    """The tier j1's decisions read for ``peer`` (bounded under the policy)."""
    rp._compute_reputation(peer, None, None, respond=False)
    told = rp.reputations[peer] if peer in rp.reputations.current else None
    if told is None:
        return 0
    read = rp._bounded(peer, told) if rp.join_policy.enabled else told
    return rp._trust_tier(read)


def simulate(colluders: int, adversary: str, policy_on: bool, *,
             horizon: float = 3600.0, probe_interval: float = 60.0,
             burst_interval: float = 5.0, burst_k: int = 3,
             task_interval: float = 60.0, seed: float = 0.8) -> Result:
    """One run. ``adversary`` is ``fail`` or ``pass``."""
    from autonomous_trust.core._python.reputation.reputation import TX_CHANNEL_PROBE
    from autonomous_trust.core._python.identity.group import Group
    from autonomous_trust.core._python.identity.encrypt import Encryptor

    j1 = uuid5(_NS, 'j1')
    j2 = uuid5(_NS, 'j2')
    horde = [uuid5(_NS, 'colluder-%d' % i) for i in range(colluders)]
    peers = [SimpleNamespace(uuid=str(u), address='10.0.1.%d' % i,
                             nickname='p%d' % i)
             for i, u in enumerate([j2] + horde)]
    rp = _process(policy_on, j1, peers)

    # Told evidence, adopted by catch-up before j1 holds anything of its own.
    chain = rp.history
    for _ in range(TOLD_ROUNDS):
        for i, a in enumerate(horde):
            b = horde[(i + 1) % len(horde)]
            _pair(chain, uuid4(), a, INFLATE, b, INFLATE)
            _pair(chain, uuid4(), a, SLANDER, j2, GOOD_WORK)
    if policy_on:
        rp._catchup_marks = {'': set(range(len(chain)))}
        # j2 is a verified contact: an anchor, and in the anchored cohort.
        rp.protocol.anchored = frozenset({str(j2)})
        rp.protocol.anchored_cohort = Group(
            uuid4(), {str(j1): '10.0.0.1', str(j2): '10.0.1.0'}, 'anchored',
            Encryptor.generate(), False)
    rp._offer_seed('first_contact', j2, seed, 'verified contact')
    # Each colluder's told score as catch-up leaves it: where the cohort's
    # inflation puts it.
    for u in horde:
        rp.reputations.update(u, INFLATE)

    told_tier_unprobed = max(_tier_of(rp, u) for u in horde)

    # The schedule: (time, kind, peer). Burst first under the policy.
    events = []
    t = 0.0
    if policy_on:
        for _round in range(burst_k):
            for u in horde:
                events.append((t, 'probe', u))
                t += burst_interval
    cycle = [j2] + horde
    t_probe, n = t, 0
    while t_probe <= horizon:
        events.append((t_probe, 'probe', cycle[n % len(cycle)]))
        n += 1
        t_probe += probe_interval
    t_task = task_interval
    while t_task <= horizon:
        events.append((t_task, 'task', j2))
        t_task += task_interval
    events.sort(key=lambda e: (e[0], e[1]))

    work_chain = (rp._chain_for_group(str(rp.protocol.anchored_cohort.uuid))
                  if policy_on else rp.history)
    t_honest = t_colluders = None
    for when, kind, peer in events:
        if kind == 'probe':
            verdict = (PASS if peer == j2 or adversary == 'pass' else FAIL)
            target = work_chain if peer == j2 else rp.history
            _pair(target, uuid4(), j1, verdict, peer, GOOD_WORK,
                  a_channel=TX_CHANNEL_PROBE)
        else:
            _pair(work_chain, uuid4(), j1, GOOD_WORK, j2, GOOD_WORK)
        if t_honest is None and _tier_of(rp, j2) >= HONEST_TIER:
            t_honest = when
        if adversary == 'fail' and t_colluders is None \
                and all(_tier_of(rp, u) < 1 for u in horde):
            t_colluders = when
        if t_honest is not None and (adversary == 'pass' or t_colluders is not None):
            break
    return Result(colluders, adversary, policy_on, t_honest, t_colluders,
                  told_tier_unprobed)


def sweep(sizes=(4, 8, 16, 32)) -> list[Result]:
    """Every combination of cohort size, adversary and policy."""
    with tempfile.TemporaryDirectory() as root:
        os.environ.setdefault('AUTONOMOUS_TRUST_ROOT', root)
        os.makedirs(os.path.join(root, 'etc', 'at'), exist_ok=True)
        return [simulate(n, adv, pol)
                for n in sizes for adv in ('fail', 'pass') for pol in (False, True)]


def _fmt(v):
    return '-' if v is None else '%.0f s' % v


def main():
    print('| colluders | adversary | policy | j2 trusted | colluders low | '
          'told tier, unprobed |')
    print('|---|---|---|---|---|---|')
    for r in sweep():
        print('| %d | %s | %s | %s | %s | %d |' % (
            r.colluders, r.adversary, 'on' if r.policy else 'off',
            _fmt(r.t_honest),
            _fmt(r.t_colluders) if r.adversary == 'fail' else 'n/a',
            r.told_tier_unprobed))


if __name__ == '__main__':
    main()
