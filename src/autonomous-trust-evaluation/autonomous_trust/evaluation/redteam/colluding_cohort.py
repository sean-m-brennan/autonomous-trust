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
"""A colluding cohort, live: the hostile-join evaluation in containers
(RD_14.4_HOSTILE_JOIN_PLAN.md Phase 6).

N colluders form a cohort; two honest joiners, verified first-contact contacts
of each other, join it, with or without the join policy. The colluders write
inflated scores of each other and slanderous scores of everyone else, and
either fail AT's known-answer probes or pass them. The joiners log their
reputation view (``AT_REP_DUMP_SEC``), and ``collect`` reads off how long they
took to hold each peer at its correct tier.

Unlike the other attacks this one is self-contained: ``compose`` builds the
whole deployment, and every container runs ``node_main`` (``python -m
autonomous_trust.evaluation.redteam.colluding_cohort``), which prepares its
own configuration before it starts the node in the same process:

- **Identity** is generated in the container, so it carries the container's
  own address.
- **A colluder** swaps its reputation process for ``ColludingReputationProcess``
  (``subsystems.cfg.json``) and, for the ``fail`` adversary, replaces the
  bootstrap probe answers with wrong ones before the node registers them.
- **A joiner** publishes its public identity to the shared volume, waits for
  the other joiner's, records it as a verified contact, and declares the join
  policy when the run has it on.

Run it with ``RedteamHarness`` (which brings a ``standalone`` compose up and
down itself) or ``scripts/test-hostile-join.sh`` on a host with docker; not in
the Claude sandbox.
"""

from __future__ import annotations

import json
import os
import re
import time

from autonomous_trust.core._python.reputation.repprocess import ReputationProcess
from autonomous_trust.core._python.processes import ProcMeta
from autonomous_trust.evaluation.redteam import AttackScenario

#: Scores a colluder gives a fellow colluder, and anyone else.
INFLATE, SLANDER = 0.95, 0.1
#: Nicknames: a colluder's starts with this, so its fellows know it.
COLLUDER_PREFIX = 'colluder-'
JOINERS = ('joiner-1', 'joiner-2')
#: Where the joiners exchange public identities (a shared volume).
SHARED_DIR = '/shared'
#: The image every node runs; it must carry the evaluation and first-contact
#: packages.
DEFAULT_IMAGE = 'autonomous-trust-full-devel'


class ColludingReputationProcess(ReputationProcess, metaclass=ProcMeta,
                                 proc_name='reputation',
                                 description='Reputation (colluding)'):
    """A colluder's reputation process: every half it proposes scores a fellow
    colluder INFLATE and anyone else SLANDER, whatever the work was. Keeps the
    ``reputation`` process name, so every queue and peer lookup reaches it."""

    def _start_paxos(self, queues, score, group_uuid=None):
        subject = getattr(score, 'subject_uuid', None)
        peer = self.peers.find_by_uuid(subject) if subject is not None else None
        nick = getattr(peer, 'nickname', '') or ''
        score.score = INFLATE if nick.startswith(COLLUDER_PREFIX) else SLANDER
        return super()._start_paxos(queues, score, group_uuid)


def fail_probes():
    """Answer every known-answer probe wrongly: the ``fail`` adversary. Must
    run before the node registers its bootstrap capabilities."""
    from autonomous_trust.core._python import bootstrap_capabilities as bc
    bc.BOOTSTRAP_FUNCTIONS['at.handshake'] = lambda nonce=0, **_: int(nonce) + 2
    bc.BOOTSTRAP_FUNCTIONS['at.time-attest'] = lambda **_: 0.0
    bc.BOOTSTRAP_FUNCTIONS['at.echo-challenge'] = \
        lambda payload='', **_: str(payload)[::-1] + '!'


# --- the deployment ----------------------------------------------------------

def join_policy_doc() -> dict:
    """The joiners' declaration: verified contacts are anchors, defaults else."""
    return {'version': 1, 'enabled': True, 'anchors': ['verified_contact']}


def compose(colluders: int, adversary: str, policy: bool, *,
            image: str = DEFAULT_IMAGE, dump_sec: float = 5.0,
            joiner_delay: int = 60) -> dict:
    """The deployment as a compose document: the colluders first, so the
    cohort exists, then the two joiners."""
    if adversary not in ('fail', 'pass'):
        raise ValueError('adversary is fail or pass')
    services = {}
    names = ['%s%d' % (COLLUDER_PREFIX, i + 1) for i in range(colluders)]
    for i, name in enumerate(names + list(JOINERS)):
        joiner = name in JOINERS
        env = {
            'AT_REDTEAM_ROLE': 'joiner' if joiner else 'colluder',
            'AT_REDTEAM_ADVERSARY': adversary,
            'AT_REDTEAM_POLICY': '1' if policy else '0',
            'AT_PEER_NAME': name,
            'AT_FIRST_CONTACT': '1',
            'AUTONOMOUS_TRUST_BACKEND': 'python',
            'AUTONOMOUS_TRUST_EXE': '-m autonomous_trust.evaluation.redteam.colluding_cohort',
            'STARTUP_DELAY': str(joiner_delay if joiner else 0),
        }
        if joiner:
            env['AT_REP_DUMP_SEC'] = str(dump_sec)
        services[name] = {
            'image': image,
            'container_name': name,
            'hostname': name,
            'environment': env,
            'volumes': ['shared:%s' % SHARED_DIR],
            'networks': {'cohort': {'ipv4_address': '10.29.0.%d' % (10 + i)}},
        }
    return {
        'services': services,
        'volumes': {'shared': {}},
        'networks': {'cohort': {'ipam': {'config': [{'subnet': '10.29.0.0/24'}]}}},
    }


# --- the container side ------------------------------------------------------

def prepare(cfg_dir: str, name: str, role: str, adversary: str, policy: bool,
            shared_dir: str = SHARED_DIR, wait_sec: float = 300.0):
    """This node's configuration, before it starts. Returns the join-policy
    path to export, or None."""
    from autonomous_trust.core.config.generate import random_config
    from autonomous_trust.core._python.processes import ProcessTracker
    from autonomous_trust.core import Configuration, CfgIds
    from autonomous_trust.core._python.identity.identity import (
        public_identity_to_canonical, public_identity_from_canonical)

    os.makedirs(cfg_dir, exist_ok=True)
    random_config(cfg_dir, name)       # what `python -m autonomous_trust --live` does
    identity = Configuration.from_file(
        os.path.join(cfg_dir, CfgIds.identity + Configuration.file_ext))
    if role == 'colluder':
        path = os.path.join(cfg_dir, ProcessTracker.default_filename)
        with open(path) as f:
            subsystems = json.load(f)
        subsystems[CfgIds.reputation] = '%s.%s' % (
            ColludingReputationProcess.__module__,
            ColludingReputationProcess.__qualname__)
        with open(path, 'w') as f:
            json.dump(subsystems, f, indent=2)
        if adversary == 'fail':
            fail_probes()
        return None

    # A joiner: swap public identities with the other one, then record it.
    os.makedirs(shared_dir, exist_ok=True)
    mine = os.path.join(shared_dir, name + '.json')
    with open(mine + '.tmp', 'w') as f:
        json.dump(public_identity_to_canonical(identity.publish()), f)
    os.replace(mine + '.tmp', mine)
    other = [j for j in JOINERS if j != name][0]
    theirs = os.path.join(shared_dir, other + '.json')
    deadline = time.time() + wait_sec
    while not os.path.exists(theirs):
        if time.time() > deadline:
            raise RuntimeError('%s: no public identity from %s' % (name, other))
        time.sleep(1.0)
    with open(theirs) as f:
        peer = public_identity_from_canonical(json.load(f))
    from autonomous_trust.first_contact import (Contact, Contacts, Provenance,
                                                FIRST_CONTACT_VERIFIED_SEED)
    store = Contacts()
    contact = Contact(peer, petname=other, provenance=Provenance.token)
    contact.mark_verified(FIRST_CONTACT_VERIFIED_SEED)
    store.add(contact)
    store.save()
    if not policy:
        return None
    policy_path = os.path.join(cfg_dir, 'join_policy.json')
    with open(policy_path, 'w') as f:
        json.dump(join_policy_doc(), f)
    return policy_path


def node_main():
    """The container's entry point: prepare, then run the node here."""
    from autonomous_trust.core import AutonomousTrust, Configuration
    from autonomous_trust.core._python.processes import LogLevel
    name = os.environ.get('AT_PEER_NAME', 'node')
    policy_path = prepare(Configuration.get_cfg_dir(), name,
                          os.environ.get('AT_REDTEAM_ROLE', 'colluder'),
                          os.environ.get('AT_REDTEAM_ADVERSARY', 'fail'),
                          os.environ.get('AT_REDTEAM_POLICY') == '1')
    if policy_path is not None:
        os.environ['AT_JOIN_POLICY'] = policy_path
    AutonomousTrust(multiproc=True, log_level=LogLevel.INFO,
                    logfile=Configuration.log_stdout).run_forever()


# --- reading the result ------------------------------------------------------

_DUMP = re.compile(r'AT_REPDUMP (\{.*\})')


def collect(log_text: str, adversary: str, honest_tier: int = 3) -> dict:
    """From one joiner's log: seconds from its first dump until it held the
    other joiner at ``honest_tier`` or above, until every colluder sat below
    tier 1 (``fail`` adversary only), and the highest tier it gave a colluder
    before it held any bilateral evidence of that colluder."""
    t0 = t_honest = t_colluders = None
    told_tier = 0
    for line in log_text.splitlines():
        m = _DUMP.search(line)
        if m is None:
            continue
        try:
            rec = json.loads(m.group(1))
        except ValueError:
            continue
        t = float(rec.get('t', 0.0))
        t0 = t if t0 is None else t0
        view = rec.get('view') or []
        colluders = [v for v in view
                     if (v.get('nick') or '').startswith(COLLUDER_PREFIX)]
        joiners = [v for v in view if (v.get('nick') or '') in JOINERS]
        for v in colluders:
            if not v.get('n'):
                told_tier = max(told_tier, int(v.get('tier', 0)))
        if t_honest is None and any(int(v.get('tier', 0)) >= honest_tier
                                    for v in joiners):
            t_honest = t - t0
        if adversary == 'fail' and t_colluders is None and colluders \
                and all(int(v.get('tier', 0)) < 1 for v in colluders):
            t_colluders = t - t0
    return {'t_honest': t_honest, 't_colluders': t_colluders,
            'told_tier_unprobed': told_tier}


class ColludingCohortAttack(AttackScenario):
    """The hostile-join evaluation as a red-team scenario. ``setup`` hands the
    harness a standalone compose: the whole deployment, run as it stands."""

    name = 'colluding_cohort'
    description = 'Two honest joiners entering a colluding cohort'

    def __init__(self, colluders: int = 8, adversary: str = 'fail',
                 policy: bool = True, image: str = DEFAULT_IMAGE):
        self.colluders = colluders
        self.adversary = adversary
        self.policy = policy
        self.image = image

    def setup(self, sim_config: dict, compose_config: dict) -> None:
        compose_config.clear()
        compose_config.update(compose(self.colluders, self.adversary,
                                      self.policy, image=self.image))
        compose_config['standalone'] = True
        sim_config['collect_logs'] = list(JOINERS)

    def collect(self, metrics: dict) -> dict:
        logs = metrics.get('logs') or {}
        metrics['attack_specific'] = {
            'colluders': self.colluders,
            'adversary': self.adversary,
            'policy': self.policy,
            'joiners': {j: collect(logs.get(j, ''), self.adversary)
                        for j in JOINERS},
        }
        return metrics


if __name__ == '__main__':
    node_main()
