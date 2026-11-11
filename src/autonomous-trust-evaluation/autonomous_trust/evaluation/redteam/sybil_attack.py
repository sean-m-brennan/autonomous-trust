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
"""A Sybil attack, live: cheap identities that join an honest cohort, inflate
each other and slander everyone else.

AT admits every fresh keypair: admission checks the build, key reuse and the
identity's own validity, not how many identities one operator runs. So this
attack does not gate on admission. It reports, as findings, how many
members the honest nodes hand the group key to (``admitted``, from their
``Rotated group key`` and ``Sending group update`` lines) and how many Sybils
each honest node holds as peers (``sybils_seen``), and gates on *influence*:

- every honest node still holds every other honest node at tier 3 on its own
  evidence at the end, whatever the Sybils say of them;
- no honest node gives a Sybil a tier above the ceiling for a peer it holds
  no own evidence of. With the join policy that ceiling is its ``told_tier``
  (``TOLD_TIER_DEFAULT``); without it, ``UNVERIFIED_RESTORE_TIER``.

The deployment is standalone. ``honest`` nodes run ``live`` and dump their
reputation view; ``sybil`` nodes start ``sybil_delay`` seconds later, run
this module, and swap in ``SybilReputationProcess`` (the colluding cohort's
inflate-and-slander, with ``sybil-`` as the fellow marker). They answer
probes correctly: a cheap Sybil does honest work.
"""

from __future__ import annotations

import os
import re

from autonomous_trust.evaluation.redteam import AttackScenario
from autonomous_trust.evaluation.redteam import live
from autonomous_trust.evaluation.redteam.colluding_cohort import (
    ColludingReputationProcess)
from autonomous_trust.core._python.processes import ProcMeta

SYBIL_PREFIX = 'sybil-'
HONEST_PREFIX = 'honest-'
SUBNET = '10.33.0'


class SybilReputationProcess(ColludingReputationProcess, metaclass=ProcMeta,
                             proc_name='reputation',
                             description='Reputation (Sybil)'):
    """Inflates fellow Sybils, slanders everyone else."""

    fellow_prefix = SYBIL_PREFIX


def told_ceiling(policy: bool) -> int:
    """The highest tier an honest node may give a peer it holds no own
    evidence of."""
    if policy:
        from autonomous_trust.core._python.identity.join_policy import (
            TOLD_TIER_DEFAULT)
        return TOLD_TIER_DEFAULT
    from autonomous_trust.core._python.reputation.repprocess import (
        ReputationProcess)
    return ReputationProcess.UNVERIFIED_RESTORE_TIER


# --- the deployment ----------------------------------------------------------

def compose(sybils: int = 6, honest: int = 6, *, sybil_delay: int = 120,
            image: str = live.DEFAULT_IMAGE, dump_sec: float = 5.0,
            policy: bool = True, log_level: str = 'INFO') -> dict:
    """The honest cohort at once, the Sybils ``sybil_delay`` seconds later."""
    services = {}
    for i in range(honest):
        name = '%s%d' % (HONEST_PREFIX, i + 1)
        services[name] = live.honest_service(
            name, '%s.%d' % (SUBNET, 10 + i), image=image, policy=policy,
            dump_sec=dump_sec, log_level=log_level)
    for i in range(sybils):
        name = '%s%d' % (SYBIL_PREFIX, i + 1)
        services[name] = live.node_service(
            name, '%s.%d' % (SUBNET, 100 + i), 'sybil',
            {'AT_REDTEAM_LOG_LEVEL': log_level,
             'STARTUP_DELAY': str(sybil_delay)},
            image=image, module=__name__)
    return live.deployment(services, '%s.0/24' % SUBNET)


# --- the container side ------------------------------------------------------

def prepare(cfg_dir: str, name: str) -> None:
    """A Sybil's configuration: a fresh identity with the inflate-and-slander
    reputation process. Its probe answers stay the honest ones."""
    from autonomous_trust.core import CfgIds
    live.base_config(cfg_dir, name)
    live.swap_process(cfg_dir, CfgIds.reputation, SybilReputationProcess)


def node_main():
    from autonomous_trust.core import Configuration
    prepare(Configuration.get_cfg_dir(), os.environ.get('AT_PEER_NAME', 'node'))
    live.run_node(os.environ.get('AT_REDTEAM_LOG_LEVEL', 'INFO'))


# --- reading the result ------------------------------------------------------

#: The members a node hands the group key to: at a rotation, and in each
#: group update it sends.
_ROTATED = re.compile(r'(?:Rotated group key to epoch \d+ \(|Sending group '
                      r'update with key \S+ epoch \d+ \(carries_key=\d\) to )'
                      r'(\d+) member')


def collect_node(log_text: str, name: str, honest: list,
                 honest_tier: int = 3) -> dict:
    """From one honest node's log: ``t_honest`` (when it last came to hold
    every other honest node at ``honest_tier`` on own evidence, and kept
    them there), the highest tier it gave a Sybil with no own evidence
    (``sybil_tier_unearned``) and at all (``sybil_tier_max``), how many
    Sybils it saw, and the most members it counted at a key rotation."""
    dumps = live.read_dumps(log_text)
    unearned = top = 0
    seen = set()
    for rec in dumps:
        for v in rec.get('view') or []:
            nick = live.short_nick(v)
            if not nick.startswith(SYBIL_PREFIX):
                continue
            seen.add(nick)
            tier = int(v.get('tier', 0))
            top = max(top, tier)
            if not v.get('own'):
                unearned = max(unearned, tier)
    admitted = [int(m) for m in _ROTATED.findall(log_text)]
    return {
        'dumps': len(dumps),
        't_honest': live.honest_held_since(dumps, name, honest, honest_tier),
        'sybil_tier_unearned': unearned,
        'sybil_tier_max': top,
        'sybils_seen': len(seen),
        'admitted': max(admitted, default=0),
    }


class SybilAttack(AttackScenario):
    """Sybils entering an honest cohort, as a standalone red-team scenario."""

    name = 'sybil_attack'
    description = 'Cheap identities inflating each other and slandering the rest'

    def __init__(self, sybils: int = 6, honest: int = 6, *,
                 sybil_delay: int = 120, image: str = live.DEFAULT_IMAGE,
                 policy: bool = True, log_level: str = 'INFO'):
        self.sybils = sybils
        self.honest = honest
        self.sybil_delay = sybil_delay
        self.image = image
        self.policy = policy
        self.log_level = log_level
        self.ceiling = told_ceiling(policy)

    @property
    def honest_names(self) -> list:
        return ['%s%d' % (HONEST_PREFIX, i + 1) for i in range(self.honest)]

    def setup(self, sim_config: dict, compose_config: dict) -> None:
        compose_config.clear()
        compose_config.update(compose(
            self.sybils, self.honest, sybil_delay=self.sybil_delay,
            image=self.image, policy=self.policy, log_level=self.log_level))
        compose_config['standalone'] = True
        sim_config['collect_logs'] = self.honest_names

    def collect(self, metrics: dict) -> dict:
        logs = metrics.get('logs') or {}
        nodes = {n: collect_node(logs.get(n, ''), n, self.honest_names)
                 for n in self.honest_names}
        failed = []
        for n, r in nodes.items():
            if r['t_honest'] is None:
                failed += live.honest_pair_failures(
                    n, live.read_dumps(logs.get(n, '')), self.honest_names) \
                    or ['%s: honest tier not held to the end' % n]
            if r['sybil_tier_unearned'] > self.ceiling:
                failed.append('%s: unearned Sybil tier %d above ceiling %d' % (
                    n, r['sybil_tier_unearned'], self.ceiling))
        metrics['attack_specific'] = {
            'sybils': self.sybils,
            'honest': self.honest,
            'sybil_delay': self.sybil_delay,
            'policy': self.policy,
            'ceiling': self.ceiling,
            'nodes': nodes,
            'admitted_max': max((r['admitted'] for r in nodes.values()),
                                default=0),
            'sybils_seen_max': max((r['sybils_seen'] for r in nodes.values()),
                                   default=0),
            'failed_checks': failed,
        }
        silent = [n for n, r in nodes.items() if not r['dumps']]
        if not silent and not any(r['sybils_seen'] for r in nodes.values()):
            # No honest node ever held a Sybil as a peer: the Sybils never
            # ran (or never joined), and an untouched cohort is no result.
            silent = ['%s%d' % (SYBIL_PREFIX, i + 1) for i in range(self.sybils)]
        live.mark_no_data(metrics, logs, silent)
        return metrics


if __name__ == '__main__':
    node_main()
