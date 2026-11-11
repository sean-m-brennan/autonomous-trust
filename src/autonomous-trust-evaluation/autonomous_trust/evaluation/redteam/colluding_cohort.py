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
- **Plaintext verbs** of every enabled extension are granted
  (``unencrypted_verbs.cfg.json``), since every node runs first contact.
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
import time

from autonomous_trust.core._python.reputation.repprocess import ReputationProcess
from autonomous_trust.core._python.reputation.reputation import score_to_milli
from autonomous_trust.core._python.processes import ProcMeta
from autonomous_trust.evaluation.redteam import AttackScenario
from autonomous_trust.evaluation.redteam.live import (
    DEFAULT_IMAGE, RedTeamNode, base_config, held_since, read_dumps,
    run_node, swap_process)

#: Scores a colluder gives a fellow colluder, and anyone else.
INFLATE, SLANDER = 0.95, 0.1
#: Nicknames: a colluder's starts with this, so its fellows know it.
COLLUDER_PREFIX = 'colluder-'
JOINERS = ('joiner-1', 'joiner-2')
#: Where the joiners exchange public identities (a shared volume).
SHARED_DIR = '/shared'


class ColludingReputationProcess(ReputationProcess, metaclass=ProcMeta,
                                 proc_name='reputation',
                                 description='Reputation (colluding)'):
    """A colluder's reputation process: every half it proposes scores a fellow
    colluder INFLATE and anyone else SLANDER, whatever the work was. Keeps the
    ``reputation`` process name, so every queue and peer lookup reaches it.
    A fellow is a peer whose nickname starts with ``fellow_prefix``."""

    fellow_prefix = COLLUDER_PREFIX

    def _start_paxos(self, queues, score, group_uuid=None):
        subject = getattr(score, 'subject_uuid', None)
        peer = self.peers.find_by_uuid(subject) if subject is not None else None
        nick = getattr(peer, 'nickname', '') or ''
        score.score_milli = score_to_milli(
            INFLATE if nick.startswith(self.fellow_prefix) else SLANDER)
        return super()._start_paxos(queues, score, group_uuid)


# The wrong answers are module-level functions, not lambdas: the node hands
# its processes to a multiprocessing pool, which pickles them, and a lambda
# cannot be pickled, so a colluder holding lambdas dies at start-up.

def _wrong_handshake(nonce=0, **_):
    return int(nonce) + 2


def _wrong_time_attest(**_):
    return 0.0


def _wrong_echo_challenge(payload='', **_):
    return str(payload)[::-1] + '!'


def fail_probes():
    """Answer every known-answer probe wrongly: the ``fail`` adversary. Must
    run before the node registers its bootstrap capabilities."""
    from autonomous_trust.core._python import bootstrap_capabilities as bc
    bc.BOOTSTRAP_FUNCTIONS['at.handshake'] = _wrong_handshake
    bc.BOOTSTRAP_FUNCTIONS['at.time-attest'] = _wrong_time_attest
    bc.BOOTSTRAP_FUNCTIONS['at.echo-challenge'] = _wrong_echo_challenge


# --- the deployment ----------------------------------------------------------

def join_policy_doc() -> dict:
    """The joiners' declaration: verified contacts are anchors, defaults else."""
    return {'version': 1, 'enabled': True, 'anchors': ['verified_contact']}


def compose(colluders: int, adversary: str, policy: bool, *,
            image: str = DEFAULT_IMAGE, dump_sec: float = 5.0,
            joiner_delay: int = 60, log_level: str = 'INFO') -> dict:
    """The deployment as a compose document: the colluders first, so the
    cohort exists, then the two joiners. ``log_level`` is a ``LogLevel``
    name every node logs at."""
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
            'AT_REDTEAM_LOG_LEVEL': log_level,
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
    from autonomous_trust.core import CfgIds
    from autonomous_trust.core._python.identity.identity import (
        public_identity_to_canonical, public_identity_from_canonical)

    identity = base_config(cfg_dir, name)
    if role == 'colluder':
        swap_process(cfg_dir, CfgIds.reputation, ColludingReputationProcess)
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
    from autonomous_trust.core import Configuration
    name = os.environ.get('AT_PEER_NAME', 'node')
    policy_path = prepare(Configuration.get_cfg_dir(), name,
                          os.environ.get('AT_REDTEAM_ROLE', 'colluder'),
                          os.environ.get('AT_REDTEAM_ADVERSARY', 'fail'),
                          os.environ.get('AT_REDTEAM_POLICY') == '1')
    if policy_path is not None:
        os.environ['AT_JOIN_POLICY'] = policy_path
    run_node(os.environ.get('AT_REDTEAM_LOG_LEVEL', 'INFO'))


# --- reading the result ------------------------------------------------------

def collect(log_text: str, adversary: str, honest_tier: int = 3) -> dict:
    """From one joiner's log: seconds from its first dump until it held the
    other joiner at ``honest_tier`` or above, until every colluder sat below
    tier 1 (``fail`` adversary only), and the highest tier it gave a colluder
    before it held any bilateral evidence of that colluder. ``dumps`` counts
    the dumps read: 0 means the joiner never ran, so the times say nothing.

    A tier counts only once the joiner holds bilateral evidence of that peer
    (the dump's ``own``, its own entries across every chain it reads). The
    hostile-join run of 2026-11-04 read ``t_colluders`` at 5 s, the first
    dump, where every peer starts below tier 1 with no evidence at all. A
    dump without ``own`` (an older build) counts as no evidence.

    A time counts only if it holds: ``t_honest`` and ``t_colluders`` are when
    the condition last became true and stayed true through the last dump,
    None if it did not hold at the end. ``t_honest_first`` and
    ``t_colluders_first`` keep the first crossing. Without the policy, the
    runs of 2026-11-04 crossed the honest tier at 63 s and lost it to the
    cohort's slander by 180 s for good."""
    series = {'t_honest': [], 't_colluders': []}
    first = {'t_honest': None, 't_colluders': None}
    told_tier = 0
    dumps = read_dumps(log_text)
    t0 = float(dumps[0].get('t', 0.0)) if dumps else 0.0
    for rec in dumps:
        t = float(rec.get('t', 0.0))
        view = rec.get('view') or []
        colluders = [v for v in view
                     if (v.get('nick') or '').startswith(COLLUDER_PREFIX)]
        # A live nickname is a full address (joiner-2@tekfive.com).
        joiners = [v for v in view
                   if (v.get('nick') or '').split('@')[0] in JOINERS]
        for v in colluders:
            if not v.get('own'):
                told_tier = max(told_tier, int(v.get('tier', 0)))
        now = {'t_honest': any(int(v.get('tier', 0)) >= honest_tier
                               and v.get('own') for v in joiners),
               't_colluders': adversary == 'fail' and bool(colluders)
               and all(int(v.get('tier', 0)) < 1 and v.get('own')
                       for v in colluders)}
        for what, ok in now.items():
            series[what].append((t, ok))
            if ok and first[what] is None:
                first[what] = t - t0
    held = {what: held_since(s) for what, s in series.items()}
    return {**held, 't_honest_first': first['t_honest'],
            't_colluders_first': first['t_colluders'],
            'told_tier_unprobed': told_tier, 'dumps': len(dumps)}


class ColludingCohortAttack(AttackScenario):
    """The hostile-join evaluation as a red-team scenario. ``setup`` hands the
    harness a standalone compose: the whole deployment, run as it stands."""

    name = 'colluding_cohort'
    description = 'Two honest joiners entering a colluding cohort'

    def __init__(self, colluders: int = 8, adversary: str = 'fail',
                 policy: bool = True, image: str = DEFAULT_IMAGE,
                 log_level: str = 'INFO'):
        self.colluders = colluders
        self.adversary = adversary
        self.policy = policy
        self.image = image
        self.log_level = log_level

    def setup(self, sim_config: dict, compose_config: dict) -> None:
        compose_config.clear()
        compose_config.update(compose(self.colluders, self.adversary,
                                      self.policy, image=self.image,
                                      log_level=self.log_level))
        compose_config['standalone'] = True
        sim_config['collect_logs'] = list(JOINERS)

    def collect(self, metrics: dict) -> dict:
        logs = metrics.get('logs') or {}
        joiners = {j: collect(logs.get(j, ''), self.adversary) for j in JOINERS}
        # What the verdict rests on: each joiner earns the honest tier for
        # the other, and under the `fail` adversary sinks every colluder on
        # evidence. A time that never came is a failed check, and the harness
        # FAILs on any.
        failed = ['%s: %s' % (j, what) for j, r in joiners.items()
                  for what in ('t_honest', 't_colluders')
                  if r[what] is None
                  and (what == 't_honest' or self.adversary == 'fail')]
        metrics['attack_specific'] = {
            'colluders': self.colluders,
            'adversary': self.adversary,
            'policy': self.policy,
            'joiners': joiners,
            'failed_checks': failed,
        }
        if not all(r['dumps'] for r in joiners.values()):
            # A joiner that never dumped never ran (a missing module in the
            # image, say): NO_DATA, not a PASS with empty times. Keep the
            # tail of its log so the report says why.
            metrics['error'] = 'no_metrics'
            metrics['attack_specific']['log_tails'] = {
                j: logs.get(j, '')[-2000:] for j, r in joiners.items()
                if not r['dumps']}
        return metrics


if __name__ == '__main__':
    node_main()
