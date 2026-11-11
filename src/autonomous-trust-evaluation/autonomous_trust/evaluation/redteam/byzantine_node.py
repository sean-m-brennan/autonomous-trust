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
"""A Byzantine equivocator, live: one member tells each of the others a
different score for the same half.

An honest node proposes a half (its score of a transaction) as one
``transaction`` message to its group, and an acceptor signs exactly the
(peer, task, score, channel) it was shown; a commit needs a roster quorum of
those signatures. The equivocator sends a separate ``transaction`` to each
roster member instead, alternating ``score + 300`` and ``score - 300`` (clamped
to 0..1000) by recipient order, so no two neighbors in that order sign the
same score.

The deployment is standalone: ``honest`` nodes run ``live`` (and dump their
reputation view, with the primary chain's length and head), and the
``byzantine`` nodes run this module, which swaps in
``EquivocatingReputationProcess``. ``collect`` reads every honest node's log.

FAIL when the honest nodes' chains disagree: final lengths more than two
apart, or two honest nodes at one length with different heads (a fork). FAIL
too when any honest node ends without holding every other honest node at tier
3 on its own evidence. ``equivocations_logged`` (placement's ``equivocation
recorded on chain`` ERROR lines) and ``byz_commits`` (how many of the
equivocator's halves an honest node holds) are reported, not gated: an
equivocated half should not gather a quorum on one score, so ``byz_commits``
near zero is expected, and anything else is a finding.
"""

from __future__ import annotations

import os
import re

from autonomous_trust.core._python.config import from_json_string, to_json_string
from autonomous_trust.core._python.network.message import Message
from autonomous_trust.core._python.processes import ProcMeta
from autonomous_trust.core._python.reputation.protocol import ReputationProtocol
from autonomous_trust.core._python.reputation.repprocess import ReputationProcess
from autonomous_trust.core._python.system import CfgIds
from autonomous_trust.evaluation.redteam import AttackScenario
from autonomous_trust.evaluation.redteam import live

BYZ_PREFIX = 'byzantine-'
HONEST_PREFIX = 'honest-'
#: How far each side of the truth the equivocator's two stories are.
SKEW_MILLI = 300
SUBNET = '10.31.0'


def skewed(score_milli: int, i: int) -> int:
    """The score the ``i``-th recipient is told: above the truth for even
    ``i``, below it for odd, clamped to the score range."""
    if i % 2 == 0:
        return min(1000, int(score_milli) + SKEW_MILLI)
    return max(0, int(score_milli) - SKEW_MILLI)


class _Capture(object):
    """A stand-in network queue that keeps what is put on it."""

    def __init__(self):
        self.items = []

    def put(self, item, block=True, timeout=None):
        self.items.append(item)


class EquivocatingReputationProcess(ReputationProcess, metaclass=ProcMeta,
                                    proc_name='reputation',
                                    description='Reputation (equivocating)'):
    """Proposes each half as one ``transaction`` per roster member, with
    alternating scores. The body is otherwise the honest one: it is built by
    the honest ``_propose_half`` and only its score is changed, so the
    equivocator keeps up with the protocol. Keeps the ``reputation`` process
    name, so every queue and peer lookup reaches it."""

    def _recipients(self, group_uuid):
        target = self._send_target(group_uuid)
        if isinstance(target, (list, tuple)):
            members = list(target)
        else:
            members = self._members_of_group(target)
        me = str(self.identity.uuid)
        return sorted((p for p in members if str(p.uuid) != me),
                      key=lambda p: str(p.uuid))

    def _propose_half(self, queues, pax_id, score, group_uuid):
        honest = _Capture()
        super()._propose_half({CfgIds.network: honest}, pax_id, score,
                              group_uuid)
        if not honest.items:
            return
        body = from_json_string(honest.items[0].obj)
        for i, peer in enumerate(self._recipients(group_uuid)):
            told = dict(body, score_milli=skewed(body['score_milli'], i))
            msg = Message(self.name, ReputationProtocol.transaction,
                          to_json_string(told), peer, from_whom=self.identity)
            queues[CfgIds.network].put(msg, block=True, timeout=self.q_cadence)
        self.logger.debug('Equivocated a half to %d members',
                          len(self._recipients(group_uuid)))


# --- the deployment ----------------------------------------------------------

def compose(byzantines: int = 1, honest: int = 6, *,
            image: str = live.DEFAULT_IMAGE, dump_sec: float = 5.0,
            policy: bool = True, log_level: str = 'INFO') -> dict:
    """The honest nodes and the equivocators, all starting together."""
    services = {}
    for i in range(honest):
        name = '%s%d' % (HONEST_PREFIX, i + 1)
        services[name] = live.honest_service(
            name, '%s.%d' % (SUBNET, 10 + i), image=image, policy=policy,
            dump_sec=dump_sec, log_level=log_level)
    for i in range(byzantines):
        name = '%s%d' % (BYZ_PREFIX, i + 1)
        services[name] = live.node_service(
            name, '%s.%d' % (SUBNET, 100 + i), 'byzantine',
            {'AT_REDTEAM_LOG_LEVEL': log_level}, image=image, module=__name__)
    return live.deployment(services, '%s.0/24' % SUBNET)


# --- the container side ------------------------------------------------------

def prepare(cfg_dir: str, name: str, role: str) -> None:
    """A Byzantine node's configuration: the honest one, with the
    equivocating reputation process swapped in."""
    from autonomous_trust.core import CfgIds as Ids
    live.base_config(cfg_dir, name)
    if role == 'byzantine':
        live.swap_process(cfg_dir, Ids.reputation, EquivocatingReputationProcess)


def node_main():
    from autonomous_trust.core import Configuration
    prepare(Configuration.get_cfg_dir(), os.environ.get('AT_PEER_NAME', 'node'),
            os.environ.get('AT_REDTEAM_ROLE', 'byzantine'))
    live.run_node(os.environ.get('AT_REDTEAM_LOG_LEVEL', 'INFO'))


# --- reading the result ------------------------------------------------------

_EQUIVOCATION = re.compile(r'equivocation recorded on chain')


def collect_node(log_text: str) -> dict:
    """From one honest node's log: its last ``chain`` and every head it
    dumped by chain length (``heads``), how many committed transactions it
    holds with an equivocator at the end (``byz_commits``, the dump's ``n``),
    whether it ever held an equivocator as a peer, and how many
    equivocations placement logged."""
    dumps = live.read_dumps(log_text)
    view = live.last_view(dumps)
    heads = {}
    for rec in dumps:
        c = rec.get('chain')
        if c:
            heads.setdefault(int(c['len']), c.get('head'))
    return {
        'dumps': len(dumps),
        'chain': (dumps[-1].get('chain') if dumps else None),
        'heads': heads,
        'byz_seen': any(live.short_nick(v).startswith(BYZ_PREFIX)
                        for rec in dumps for v in rec.get('view') or []),
        'byz_commits': sum(int(v.get('n', 0)) for nick, v in view.items()
                           if nick.startswith(BYZ_PREFIX)),
        'equivocations_logged': len(_EQUIVOCATION.findall(log_text)),
    }


def chain_failures(chains: dict, heads: dict = None, slack: int = 2) -> list[str]:
    """Whether the honest chains agree: final lengths (``chains``, each
    node's last ``chain``) within ``slack`` of each other, and one head per
    length across every dump of every node (``heads``: node -> {length:
    head}). Comparing every dump, not only the last, finds a fork between
    nodes whose final lengths differ."""
    known = {n: c for n, c in chains.items() if c}
    out = []
    if known:
        lens = [int(c['len']) for c in known.values()]
        if max(lens) - min(lens) > slack:
            out.append('chain lengths %d..%d differ by more than %d'
                       % (min(lens), max(lens), slack))
    if heads is None:
        heads = {n: {int(c['len']): c.get('head')} for n, c in known.items()}
    by_len = {}
    for name, seen in sorted(heads.items()):
        for ln, head in seen.items():
            by_len.setdefault(ln, {}).setdefault(head, []).append(name)
    for ln, by_head in sorted(by_len.items()):
        if len(by_head) > 1:
            out.append('fork at length %d: %s' % (ln, '; '.join(
                '%s=%s' % (h, ','.join(ns)) for h, ns in sorted(by_head.items()))))
    return out


class ByzantineNodeAttack(AttackScenario):
    """Equivocators among honest nodes, as a standalone red-team scenario."""

    name = 'byzantine_node'
    description = 'An equivocating member telling each peer a different score'

    def __init__(self, byzantines: int = 1, honest: int = 6, *,
                 image: str = live.DEFAULT_IMAGE, policy: bool = True,
                 log_level: str = 'INFO'):
        self.byzantines = byzantines
        self.honest = honest
        self.image = image
        self.policy = policy
        self.log_level = log_level

    @property
    def honest_names(self) -> list:
        return ['%s%d' % (HONEST_PREFIX, i + 1) for i in range(self.honest)]

    def setup(self, sim_config: dict, compose_config: dict) -> None:
        compose_config.clear()
        compose_config.update(compose(self.byzantines, self.honest,
                                      image=self.image, policy=self.policy,
                                      log_level=self.log_level))
        compose_config['standalone'] = True
        sim_config['collect_logs'] = self.honest_names

    def collect(self, metrics: dict) -> dict:
        logs = metrics.get('logs') or {}
        nodes = {n: collect_node(logs.get(n, '')) for n in self.honest_names}
        failed = chain_failures({n: r['chain'] for n, r in nodes.items()},
                                {n: r['heads'] for n, r in nodes.items()})
        for n in self.honest_names:
            failed += live.honest_pair_failures(
                n, live.read_dumps(logs.get(n, '')), self.honest_names)
        metrics['attack_specific'] = {
            'byzantines': self.byzantines,
            'honest': self.honest,
            'policy': self.policy,
            'nodes': nodes,
            'equivocations_logged': sum(r['equivocations_logged']
                                        for r in nodes.values()),
            'byz_commits_max': max((r['byz_commits'] for r in nodes.values()),
                                   default=0),
            'failed_checks': failed,
        }
        silent = [n for n, r in nodes.items() if not r['dumps']]
        # A dump without ``chain`` (an image without the field) cannot show a
        # fork, so it is no result.
        silent += [n for n, r in nodes.items() if r['dumps'] and not r['chain']]
        if not silent and not any(r['byz_seen'] for r in nodes.values()):
            # No honest node ever held the equivocator as a peer: it never ran.
            silent = ['%s%d' % (BYZ_PREFIX, i + 1) for i in range(self.byzantines)]
        live.mark_no_data(metrics, logs, silent)
        return metrics


if __name__ == '__main__':
    node_main()
