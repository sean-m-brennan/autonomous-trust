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
"""Lone probe verdicts: a verdict from one of this node's own probes counts
as its own evidence as soon as it is recorded, without the probed peer's half
(the user's call, 2026-11-06). The hostile-join runs of 2026-11-05 counted it
only once the bilateral entry committed; at 18 nodes the colluders sat at the
probe cap and dropped 90 halves, and a peer that never writes its half was
never graded. Under the join policy only; never told; persisted. The C twin
is src/c/test/rep_lone_verdict_test.c.
"""
import json
import os
import queue
from uuid import uuid4

import pytest

from autonomous_trust.core.config import Configuration
from autonomous_trust.core.system import CfgIds
from autonomous_trust.core._python.identity.join_policy import JoinPolicy
from autonomous_trust.core._python.reputation.reputation import (
    LoneVerdict, LoneVerdicts, RETAINED_PER_PEER, TransactionScore,
    TX_CHANNEL_PROBE, score_to_milli)

from tests.a_unit.test_repprocess import _make_rep_process, _make_mock_peer

ON = JoinPolicy(enabled=True, anchors=frozenset({'verified_contact'}))


@pytest.fixture(autouse=True)
def _cfg_dir(tmp_path, monkeypatch):
    monkeypatch.setenv('AUTONOMOUS_TRUST_ROOT', str(tmp_path))
    os.makedirs(Configuration.get_cfg_dir(), exist_ok=True)


def _rp(policy=ON):
    rp = _make_rep_process()
    rp.join_policy = policy
    rp._warm_started = set()
    rp.protocol.peers.all = [_make_mock_peer(nickname='alice'),
                             _make_mock_peer(nickname='bob')]
    return rp, {CfgIds.network: queue.Queue()}


def _probe(rp, queues, peer, score, task=None, channel=TX_CHANNEL_PROBE):
    """Our verdict of ``peer`` from a known-answer probe, through the local
    entry point."""
    task = task or uuid4()
    rp.forward_transaction(queues, TransactionScore(
        task, score, capability_name='at.handshake', channel=channel,
        subject_uuid=peer))
    return task


def test_a_probe_verdict_of_ours_is_kept_even_when_the_cap_drops_its_half():
    rp, queues = _rp()
    peer = uuid4()
    cap = int(rp.MAX_PROBE_HALVES)
    for _ in range(cap + 2):
        _probe(rp, queues, peer, 0.1)
    assert len(rp.awaiting_commit) == cap
    assert len(rp.lone_verdicts.by_peer(peer)) == cap + 2


def test_an_app_score_and_a_targets_half_are_not_verdicts():
    rp, queues = _rp()
    peer = uuid4()
    rp.forward_transaction(queues, TransactionScore(
        uuid4(), 0.9, capability_name='agora-post', subject_uuid=peer))
    # The probed peer's own half: an at. capability on the task_outcome channel.
    _probe(rp, queues, peer, 0.9, channel=None)
    assert rp.lone_verdicts.by_peer(peer) == []


def test_recording_marks_the_peer_for_rescore_and_counts():
    rp, queues = _rp()
    peer = uuid4()
    _probe(rp, queues, peer, 0.1)
    assert str(peer) in rp._rescore_due
    assert str(peer) in rp._counts_due


def test_under_the_policy_lone_verdicts_are_own_evidence_everywhere():
    rp, queues = _rp()
    peer = uuid4()
    for _ in range(3):
        _probe(rp, queues, peer, 0.1)
    assert rp._own_count(peer) == 3
    # Told tit-for-tat: three 0.1s shrunk toward neutral, (0.3 + 3*0.2) / 6.
    assert rp._contrite_tit_for_tat(peer) == pytest.approx(0.15)
    rp._compute_reputation(peer, None, None, respond=False)
    assert rp.reputations.brought[str(peer)] == pytest.approx(0.15)
    assert rp._trust_tier(rp._bounded(peer, rp.reputations[peer])) == 0


def test_the_burst_count_reads_lone_verdicts():
    rp, queues = _rp()
    peer = uuid4()
    _probe(rp, queues, peer, 0.9)
    assert rp._burst_count(peer) == 1
    _probe(rp, queues, peer, 0.9)
    _probe(rp, queues, peer, 0.9)
    assert rp._burst_count(peer) is None          # graduated: 3 own entries


def test_without_the_policy_lone_verdicts_count_nowhere():
    rp, queues = _rp(JoinPolicy())
    peer = uuid4()
    for _ in range(3):
        _probe(rp, queues, peer, 0.1)
    assert rp._own_evidence(peer) == []
    assert rp._contrite_tit_for_tat(peer) == rp._prereputation_prior(peer)


def test_a_lone_verdict_is_never_a_defection():
    """No peer score of us stands behind a lone verdict, so two of them do
    not trigger the 0.49 hold."""
    rp, queues = _rp()
    peer = uuid4()
    for _ in range(10):
        _probe(rp, queues, peer, 0.9)
    assert rp._contrite_tit_for_tat(peer) == pytest.approx(
        (9.0 + 3 * 0.2) / 13)


def test_the_bilateral_entry_supersedes_its_lone_verdict():
    rp, queues = _rp()
    peer = uuid4()
    task = _probe(rp, queues, peer, 0.1)
    rp.history.update(task, rp.identity.uuid, score_to_milli(0.1),
                      TX_CHANNEL_PROBE)
    rp.history.update(task, peer, score_to_milli(0.9))
    assert rp._own_count(peer) == 1
    assert rp._contrite_tit_for_tat(peer) == pytest.approx((0.1 + 0.6) / 4)


def test_a_retained_bilateral_entry_also_supersedes_it():
    rp, queues = _rp()
    peer = uuid4()
    rp.history = rp._own_history(max_chain_len=2)
    task = _probe(rp, queues, peer, 0.1)
    rp.history.update(task, rp.identity.uuid, score_to_milli(0.1),
                      TX_CHANNEL_PROBE)
    rp.history.update(task, peer, score_to_milli(0.9))
    other_a, other_b = uuid4(), uuid4()
    for _ in range(3):
        t = uuid4()
        rp.history.update(t, other_a, score_to_milli(0.5))
        rp.history.update(t, other_b, score_to_milli(0.5))
    assert [tx.task_id for tx in rp.history.retained_by_peer(peer)] == [task]
    assert rp._own_count(peer) == 1


def test_the_store_bounds_oldest_out():
    store = LoneVerdicts(max_chain_len=200)
    peer = uuid4()
    for i in range(RETAINED_PER_PEER + 1):
        store.add(LoneVerdict(uuid4(), peer, 0.5, float(i)))
    held = store.by_peer(peer)
    assert len(held) == RETAINED_PER_PEER
    assert held[0].t == 1.0
    # The total bound, 4 * 2: another peer's eight push out the oldest.
    store = LoneVerdicts(max_chain_len=2)
    a, b = uuid4(), uuid4()
    for i in range(4):
        store.add(LoneVerdict(uuid4(), a, 0.5, float(i)))
    for i in range(6):
        store.add(LoneVerdict(uuid4(), b, 0.5, 10.0 + i))
    assert len(store) == 8
    assert [v.t for v in store.by_peer(a)] == [2.0, 3.0]


def test_the_store_survives_a_restart():
    rp, queues = _rp()
    peer = uuid4()
    for _ in range(3):
        _probe(rp, queues, peer, 0.1)
    rp._persist_history('')
    with open(rp._lone_verdicts_path()) as f:
        assert len(json.load(f)['entries']) == 3
    rp2 = _make_rep_process()
    rp2.identity = rp.identity
    rp2._load_lone_verdicts()
    assert len(rp2.lone_verdicts.by_peer(peer)) == 3


def test_writing_drops_verdicts_whose_entry_is_on_the_chain():
    rp, queues = _rp()
    peer = uuid4()
    task = _probe(rp, queues, peer, 0.1)
    _probe(rp, queues, peer, 0.1)
    rp.history.update(task, rp.identity.uuid, score_to_milli(0.1),
                      TX_CHANNEL_PROBE)
    rp.history.update(task, peer, score_to_milli(0.9))
    rp._persist_history('')
    assert [v.task_id for v in rp.lone_verdicts.by_peer(peer)] != [str(task)]
    assert len(rp.lone_verdicts.by_peer(peer)) == 1


def test_an_unreadable_file_leaves_the_store_empty():
    rp, _queues = _rp()
    with open(rp._lone_verdicts_path(), 'w') as f:
        f.write('{"schema": "9", "entries": []}')
    rp._load_lone_verdicts()
    assert len(rp.lone_verdicts) == 0


def test_a_colluder_that_never_writes_its_half_sinks_on_our_verdicts():
    """The live shape: three failed probes, no half from the peer, and no
    chain entry at all; its told standing among the cohort is high."""
    rp, queues = _rp()
    peer = uuid4()
    other = uuid4()
    rp.reputations.update(other, 0.5)
    for _ in range(5):
        t = uuid4()
        rp.history.update(t, other, score_to_milli(0.95))
        rp.history.update(t, peer, score_to_milli(0.95))
    for _ in range(3):
        _probe(rp, queues, peer, 0.0)
    rp._compute_reputation(peer, None, None, respond=False)
    assert rp._trust_tier(rp._bounded(peer, rp.reputations[peer])) == 0
