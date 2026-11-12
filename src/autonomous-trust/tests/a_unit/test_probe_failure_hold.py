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
"""Two failed probes in a row hold a peer's brought score below tier 1.

A wrong answer to a known-answer probe is a defection the prober can stand
behind on its own, but a lone verdict carries no score of us, so contrite
tit-for-tat never counted one. A gamer that answered rightly for eight
minutes and wrongly after kept tier 2..3 for twelve minutes on every honest
node (red-team batch, 2026-11-10): its long record and its honest
transactions outweighed the failures. Under the join policy the latest two
of our probe verdicts about a peer, both below 0.5, now hold its brought
score at 0.49 in either regime. The C twin is
src/c/test/rep_lone_verdict_test.c.
"""
import os
import queue
from uuid import uuid4

import pytest

from autonomous_trust.core.config import Configuration
from autonomous_trust.core.system import CfgIds
from autonomous_trust.core._python.identity.join_policy import JoinPolicy
from autonomous_trust.core._python.reputation.reputation import (
    TransactionScore, TX_CHANNEL_PROBE, score_to_milli)
from autonomous_trust.core._python.reputation.repprocess import probe_hold_of

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


def _probe(rp, queues, peer, score):
    rp.forward_transaction(queues, TransactionScore(
        uuid4(), score, capability_name='at.handshake',
        channel=TX_CHANNEL_PROBE, subject_uuid=peer))


def _brought(rp, peer):
    rp._compute_reputation(peer, None, None, respond=False)
    return rp.reputations.brought[str(peer)]


def _trusted(rp, queues, peer, n=20):
    for _ in range(n):
        _probe(rp, queues, peer, 0.9)
    assert _brought(rp, peer) > 0.8


def test_two_failed_probes_hold_a_trusted_peer_below_tier_1():
    rp, queues = _rp()
    peer = uuid4()
    _trusted(rp, queues, peer)
    _probe(rp, queues, peer, 0.1)
    _probe(rp, queues, peer, 0.1)
    assert _brought(rp, peer) == pytest.approx(0.49)
    assert rp._trust_tier(rp._bounded(peer, rp.reputations[peer])) == 0


def test_the_hold_stays_while_the_failures_continue():
    rp, queues = _rp()
    peer = uuid4()
    _trusted(rp, queues, peer)
    for _ in range(5):
        _probe(rp, queues, peer, 0.1)
        _brought(rp, peer)
    assert _brought(rp, peer) == pytest.approx(0.49)


def test_one_failed_probe_is_forgiven():
    rp, queues = _rp()
    peer = uuid4()
    _trusted(rp, queues, peer)
    _probe(rp, queues, peer, 0.1)
    assert _brought(rp, peer) > 0.5


def test_a_pass_between_failures_breaks_the_run():
    rp, queues = _rp()
    peer = uuid4()
    _trusted(rp, queues, peer)
    _probe(rp, queues, peer, 0.1)
    _probe(rp, queues, peer, 0.9)
    _probe(rp, queues, peer, 0.1)
    assert _brought(rp, peer) > 0.5


def test_clock_drift_is_not_a_failure():
    """An out-of-tolerance time attestation scores 0.5: routine drift."""
    rp, queues = _rp()
    peer = uuid4()
    _trusted(rp, queues, peer)
    _probe(rp, queues, peer, 0.5)
    _probe(rp, queues, peer, 0.5)
    assert _brought(rp, peer) > 0.5


def test_drift_between_failures_neither_counts_nor_breaks_the_run():
    """A wrong time attestation scores 0.5, the same as drift: a re-probe
    that lands on one says nothing either way (red-team rerun, 2026-11-10:
    25 of 36 honest nodes kept a defected gamer at tier 3 this way)."""
    rp, queues = _rp()
    peer = uuid4()
    _trusted(rp, queues, peer)
    _probe(rp, queues, peer, 0.1)
    _probe(rp, queues, peer, 0.5)
    _probe(rp, queues, peer, 0.1)
    assert _brought(rp, peer) == pytest.approx(0.49)


def test_a_placed_probe_still_counts_and_a_low_app_score_does_not():
    """The store drops a verdict once its entry is placed; the hold does not
    forget it. An app score of ours below 0.5 is not a probe."""
    rp, queues = _rp()
    peer = uuid4()
    me = rp.identity.uuid
    _trusted(rp, queues, peer)
    for _ in range(2):
        rp.forward_transaction(queues, TransactionScore(
            uuid4(), 0.1, capability_name='agora-post', subject_uuid=peer))
    assert _brought(rp, peer) > 0.5
    for _ in range(2):
        task = uuid4()
        rp.forward_transaction(queues, TransactionScore(
            task, 0.1, capability_name='at.handshake',
            channel=TX_CHANNEL_PROBE, subject_uuid=peer))
        rp.history.update(task, me, score_to_milli(0.1), TX_CHANNEL_PROBE)
        rp.history.update(task, peer, score_to_milli(0.9))
    rp._persist_lone_verdicts()
    assert _brought(rp, peer) == pytest.approx(0.49)


def test_probe_hold_of_reads_the_latest_two_only():
    assert probe_hold_of([0.1, 0.1])
    assert probe_hold_of([0.9, 0.1, 0.1])
    assert not probe_hold_of([0.1, 0.9])
    assert not probe_hold_of([0.1])
    assert not probe_hold_of([0.5, 0.1])
    assert not probe_hold_of(())


def test_without_the_policy_nothing_is_held():
    rp, queues = _rp(JoinPolicy())
    peer = uuid4()
    for _ in range(3):
        _probe(rp, queues, peer, 0.1)
    rp._compute_reputation(peer, None, None, respond=False)
    assert str(peer) not in (getattr(rp.reputations, 'brought', None) or {})


# --- Suspects: re-probed at once ---------------------------------------------

def _suspects(rp):
    return rp._suspects_of(rp._probe_recent)


def test_one_failed_probe_makes_a_suspect_and_the_hold_ends_it():
    rp, queues = _rp()
    peer = uuid4()
    for _ in range(3):
        _probe(rp, queues, peer, 0.9)
    assert _suspects(rp) == set()
    _probe(rp, queues, peer, 0.1)
    assert _suspects(rp) == {str(peer)}
    _probe(rp, queues, peer, 0.1)               # held: nothing left to ask
    assert _suspects(rp) == set()


def test_a_suspect_stays_a_suspect_through_drift():
    rp, queues = _rp()
    peer = uuid4()
    for _ in range(3):
        _probe(rp, queues, peer, 0.9)
    _probe(rp, queues, peer, 0.1)
    _probe(rp, queues, peer, 0.5)
    assert _suspects(rp) == {str(peer)}


def test_drift_makes_a_suspect_until_a_clear_answer():
    """A 0.5 is inconclusive: the worker asks again, and a probe with a right
    or wrong answer settles it (red-team rerun, 2026-11-10: 16 of 36 honest
    nodes met a defected gamer only through time attestations)."""
    rp, queues = _rp()
    peer = uuid4()
    for _ in range(3):
        _probe(rp, queues, peer, 0.9)
    _probe(rp, queues, peer, 0.5)
    assert _suspects(rp) == {str(peer)}
    _probe(rp, queues, peer, 0.9)
    assert _suspects(rp) == set()
    assert _brought(rp, peer) > 0.5


def test_drift_after_the_hold_makes_no_suspect():
    rp, queues = _rp()
    peer = uuid4()
    _probe(rp, queues, peer, 0.1)
    _probe(rp, queues, peer, 0.1)
    _probe(rp, queues, peer, 0.5)
    assert _suspects(rp) == set()


def test_a_pass_clears_a_suspect():
    rp, queues = _rp()
    peer = uuid4()
    _probe(rp, queues, peer, 0.1)
    _probe(rp, queues, peer, 0.9)
    assert _suspects(rp) == set()


def test_the_worker_is_told_the_suspects():
    from autonomous_trust.core._python.identity.join_policy import ProbeCounts
    rp, queues = _rp()
    worker_q = queue.Queue()
    queues[rp.BOOTSTRAP_WORKER_QUEUE] = worker_q
    peer = rp.protocol.peers.all[0].uuid
    for _ in range(3):
        _probe(rp, queues, peer, 0.9)
    rp._publish_probe_counts(queues, 0.0)
    while not worker_q.empty():
        worker_q.get_nowait()
    _probe(rp, queues, peer, 0.1)
    rp._publish_probe_counts(queues, 10.0)
    sent = worker_q.get_nowait()
    assert isinstance(sent, ProbeCounts) and sent.suspects == {str(peer)}
    _probe(rp, queues, peer, 0.9)
    rp._publish_probe_counts(queues, 20.0)
    assert worker_q.get_nowait().suspects == set()


def test_probe_counts_compare_their_suspects():
    from autonomous_trust.core._python.identity.join_policy import ProbeCounts
    assert ProbeCounts({}, {'a'}) != ProbeCounts({}, set())
    assert ProbeCounts({'a': 1}) == ProbeCounts({'a': 1}, ())


def test_a_repeated_task_counts_once():
    rp, queues = _rp()
    peer = uuid4()
    task = uuid4()
    for _ in range(2):
        rp.forward_transaction(queues, TransactionScore(
            task, 0.1, capability_name='at.handshake',
            channel=TX_CHANNEL_PROBE, subject_uuid=peer))
    assert rp._probe_recent[str(peer)] == (0.1,)
