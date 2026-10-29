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
"""The anchored cohort, reputation's half (RD_14.4_HOSTILE_JOIN_PLAN.md Phase
6, D8 (b)): a half about a member names the cohort, goes only to its members
and commits to its chain; acceptors check the group; the scorers read the
cohort chain beside the primary one. The C twin is
src/c/test/rep_cohort_test.c.
"""
import os
import queue
from types import SimpleNamespace
from uuid import uuid4

import pytest

from autonomous_trust.core.config import Configuration
from autonomous_trust.core.network.message import Message
from autonomous_trust.core.system import CfgIds
from autonomous_trust.core._python.config import to_yaml_string
from autonomous_trust.core._python.identity.encrypt import Encryptor
from autonomous_trust.core._python.identity.group import Group
from autonomous_trust.core._python.identity.join_policy import JoinPolicy
from autonomous_trust.core._python.reputation.protocol import ReputationProtocol
from autonomous_trust.core._python.reputation.reputation import (
    TransactionScore, TX_CHANNEL_PROBE)

from tests.a_unit.test_late_joiner_caps_resync import _new_identity
from tests.a_unit.test_repprocess import _make_rep_process


def _tx_body(id1, id2, proposer, score, certify=True, group=''):
    """A `transaction` proposal in its wire shape: the JSON object with named
    fields both runtimes send. `certify`/`group` of None leave the key off, as
    a half-round build's proposal did."""
    from autonomous_trust.core.config import to_json_string
    body = {'id1': id1, 'id2': id2, 'peer_uuid': str(proposer),
            'score_milli': score.score_milli, 'task_uuid': str(score.task_id)}
    if getattr(score, 'channel', None):
        body['channel'] = score.channel
    if certify is not None:
        body['certify'] = certify
    if group is not None:
        body['group'] = group
    return to_json_string(body)


ON = JoinPolicy(enabled=True, anchors=frozenset({'verified_contact'}))


@pytest.fixture(autouse=True)
def _cfg_dir(tmp_path, monkeypatch):
    monkeypatch.setenv('AUTONOMOUS_TRUST_ROOT', str(tmp_path))
    os.makedirs(Configuration.get_cfg_dir(), exist_ok=True)


# Real identities: a pairwise send addresses Identity objects.
_PEERS = {n: _new_identity(n, a) for n, a in (('ally', '10.0.0.2'),
                                              ('other', '10.0.0.3'))}


def _setup(policy=ON):
    """Self, a member `ally` and a non-member `other`, a primary group of all
    three, and the anchored cohort {self, ally}."""
    rp = _make_rep_process()
    rp.join_policy = policy
    rp._warm_started = set()
    ally, other = _PEERS['ally'], _PEERS['other']
    rp.protocol.peers = SimpleNamespace(all=[ally, other])
    me = str(rp.identity.uuid)
    rp.protocol.group = Group(uuid4(), {me: '10.0.0.1', str(ally.uuid): '10.0.0.2',
                                        str(other.uuid): '10.0.0.3'},
                              'cohort', Encryptor.generate(), False)
    cohort = Group(uuid4(), {me: '10.0.0.1', str(ally.uuid): '10.0.0.2'},
                   'anchored', Encryptor.generate(), False)
    rp.protocol.anchored_cohort = cohort
    return rp, ally, other, cohort


def _sent(net_q):
    out = []
    while not net_q.empty():
        out.append(net_q.get_nowait())
    return out


def test_a_half_about_a_member_goes_to_the_members_only():
    rp, ally, other, cohort = _setup()
    net_q = queue.Queue()
    rp._start_paxos({CfgIds.network: net_q},
                    TransactionScore(uuid4(), 0.9, subject_uuid=ally.uuid))
    (msg,) = _sent(net_q)
    assert list(msg.to_whom) == [ally]           # pairwise, not the cohort
    assert str(cohort.uuid) in str(msg.obj)
    assert list(rp.round_group.values()) == [str(cohort.uuid)]


def test_a_half_about_a_non_member_goes_to_the_primary_group():
    rp, ally, other, cohort = _setup()
    net_q = queue.Queue()
    rp._start_paxos({CfgIds.network: net_q},
                    TransactionScore(uuid4(), 0.9, subject_uuid=other.uuid))
    (msg,) = _sent(net_q)
    assert msg.to_whom is rp.group
    assert list(rp.round_group.values()) == [str(rp.group.uuid)]


def test_without_the_policy_nothing_routes_to_the_cohort():
    rp, ally, other, cohort = _setup(JoinPolicy())
    net_q = queue.Queue()
    rp._start_paxos({CfgIds.network: net_q},
                    TransactionScore(uuid4(), 0.9, subject_uuid=ally.uuid))
    (msg,) = _sent(net_q)
    assert msg.to_whom is rp.group


def test_the_cohort_has_its_own_chain_and_quorum():
    rp, ally, other, cohort = _setup()
    chain = rp._chain_for_group(str(cohort.uuid))
    assert chain is not rp.history
    assert rp._chain_key(str(cohort.uuid)) == str(cohort.uuid)
    assert rp._checkpoint_roster(str(cohort.uuid)) == 1   # ally
    assert rp._round_quorum(str(cohort.uuid)) == 1


def _proposal(rp, sender, group):
    rp._detached_sig = lambda *a, **k: 'ab'
    msg = Message(CfgIds.reputation, ReputationProtocol.transaction,
                  _tx_body(100, 1, sender.uuid,
                           TransactionScore(uuid4(), 0.8), True, group),
                  from_whom=sender)
    msg.verified = True
    net_q = queue.Queue()
    assert rp.handle_transaction({CfgIds.network: net_q}, msg) is True
    return not net_q.empty()


def test_an_acceptor_checks_the_cohort_and_unknown_groups():
    rp, ally, other, cohort = _setup()
    assert _proposal(rp, ally, str(cohort.uuid))
    assert not _proposal(rp, other, str(cohort.uuid))     # not a member
    assert not _proposal(rp, ally, str(uuid4()))          # a group not held
    assert _proposal(rp, other, str(rp.group.uuid))


def test_without_the_policy_an_unknown_group_is_accepted_as_before():
    rp, ally, other, cohort = _setup(JoinPolicy())
    assert _proposal(rp, other, str(uuid4()))


def _pair_on(chain, a, a_score, b, b_score, a_channel=None):
    task = uuid4()
    chain.update(task, a, a_score, a_channel)
    chain.update(task, b, b_score)


def test_the_scorers_read_the_cohort_chain():
    """Evidence moved to the cohort chain still counts: own evidence, brought,
    and the bound lifted at own_evidence_min."""
    rp, ally, other, cohort = _setup()
    chain = rp._chain_for_group(str(cohort.uuid))
    for _ in range(3):
        _pair_on(chain, rp.identity.uuid, 900, ally.uuid, 900)
    assert rp._own_count(ally.uuid) == 3
    rp.reputations.update(ally.uuid, 0.9)
    rp._compute_reputation(ally.uuid, None, None, respond=False)
    assert rp.reputations.brought[str(ally.uuid)] == pytest.approx(0.9, abs=0.05)
    assert rp._contrite_tit_for_tat(ally) > 0.2


def test_the_prior_does_not_read_catchup_marks_on_the_cohort_chain():
    """Marks are primary-chain indices; a cohort entry at the same index is
    not told."""
    rp, ally, other, cohort = _setup()
    third = uuid4()
    rp.reputations.update(third, 0.5)
    chain = rp._chain_for_group(str(cohort.uuid))
    _pair_on(chain, third, 900, ally.uuid, 900)
    rp._catchup_marks = {'': {0, 1, 2, 3}}
    assert rp._prereputation_prior(ally.uuid) > rp.PREREP_NEUTRAL
