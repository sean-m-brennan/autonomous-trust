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
"""Brought and told scores (RD_14.4_HOSTILE_JOIN_PLAN.md Phase 4, D3 (b)).

Under an enabled join policy a node keeps, beside the told score, a brought
score built from its own evidence alone, and each reader names the one it
reads: decisions read bounded (brought once the peer has own_evidence_min own
entries, else told capped at told_tier; an anchored peer reads told), and
exclusion reads brought + slash. With the policy off nothing changes. The C
twin is src/c/test/rep_brought_test.c.
"""
import os
import queue
from uuid import uuid4

import pytest

from autonomous_trust.core.config import Configuration
from autonomous_trust.core._python.identity.join_policy import (
    AnchoredSet, JoinPolicy)
from autonomous_trust.core._python.protocol import Protocol
from autonomous_trust.core._python.reputation.reputation import (
    Reputations, TX_CHANNEL_PROBE)

from tests.a_unit.test_repprocess import _make_rep_process

ON = JoinPolicy(enabled=True, anchors=frozenset({'verified_contact'}))
TIER1_CAP = 0.65


@pytest.fixture(autouse=True)
def _cfg_dir(tmp_path, monkeypatch):
    monkeypatch.setenv('AUTONOMOUS_TRUST_ROOT', str(tmp_path))
    os.makedirs(Configuration.get_cfg_dir(), exist_ok=True)


def _rp(policy=ON):
    rp = _make_rep_process()
    rp.join_policy = policy
    rp._warm_started = set()
    return rp


def _pair(rp, a, a_score, b, b_score, a_channel=None):
    """One bilateral entry: `a` gave `b` a_score, `b` gave `a` b_score."""
    task = uuid4()
    rp.history.update(task, a, a_score, a_channel)
    rp.history.update(task, b, b_score)
    return task


def _own(rp, peer, n, score=0.9):
    for _ in range(n):
        _pair(rp, rp.identity.uuid, score, peer, 0.9)


def _told(rp, peer, n, score=0.9):
    other = uuid4()
    rp.reputations.update(other, 0.5)
    for _ in range(n):
        _pair(rp, other, score, peer, 0.9)


def _score(rp, peer, told=None, coop=None):
    if told is not None:
        rp.reputations.update(peer, told)
    if coop is not None:
        rp._coop_mode[peer] = coop
    rp._compute_reputation(peer, None, None, respond=False)
    return rp.reputations[peer]


def test_no_own_evidence_no_brought_and_bounded_capped():
    rp, peer = _rp(), uuid4()
    _told(rp, peer, 3, 0.95)
    told = _score(rp, peer, told=0.95, coop=True)
    assert told == pytest.approx(0.95)
    assert str(peer) not in rp.reputations.brought
    assert rp._bounded(peer, told) == pytest.approx(TIER1_CAP, abs=1e-6)
    assert rp._trust_tier(rp._bounded(peer, told)) == 1


def test_own_evidence_min_lifts_the_bound_to_brought():
    rp, peer = _rp(), uuid4()
    _own(rp, peer, 3, 0.9)
    _told(rp, peer, 3, 0.3)
    told = _score(rp, peer, told=0.9, coop=True)
    assert rp.reputations.brought[str(peer)] == pytest.approx(0.9)
    assert rp._bounded(peer, told) == pytest.approx(0.9)


def test_short_of_own_evidence_min_stays_capped():
    rp, peer = _rp(), uuid4()
    _own(rp, peer, 2, 0.9)
    told = _score(rp, peer, told=0.9, coop=True)
    assert rp.reputations.brought[str(peer)] == pytest.approx(0.9)
    assert rp._bounded(peer, told) == pytest.approx(TIER1_CAP, abs=1e-6)


def test_own_evidence_min_is_declared():
    rp, peer = _rp(JoinPolicy(enabled=True, own_evidence_min=2)), uuid4()
    _own(rp, peer, 2, 0.9)
    told = _score(rp, peer, told=0.9, coop=True)
    assert rp._bounded(peer, told) == pytest.approx(0.9)


def test_told_tier_is_declared():
    rp, peer = _rp(JoinPolicy(enabled=True, told_tier=2)), uuid4()
    _told(rp, peer, 3, 0.95)
    told = _score(rp, peer, told=0.95, coop=True)
    assert rp._trust_tier(rp._bounded(peer, told)) == 2


def test_an_anchored_peer_reads_told():
    rp, peer = _rp(), uuid4()
    _told(rp, peer, 3, 0.95)
    told = _score(rp, peer, told=0.95, coop=True)
    rp.protocol.anchored = frozenset({str(peer)})
    assert rp._bounded(peer, told) == pytest.approx(0.95)


def _probe(rp, peer, n, score=0.9):
    """``n`` probes of ours: bilateral entries whose half of ours is on the
    probe channel."""
    for _ in range(n):
        _pair(rp, rp.identity.uuid, score, peer, 0.9, a_channel=TX_CHANNEL_PROBE)


def test_a_probe_verdict_is_own_evidence_under_the_policy():
    """Phase 5 (the user's call, 2026-10-27): a verdict counts toward
    own_evidence_min and into brought, with its score."""
    rp, peer = _rp(), uuid4()
    _probe(rp, peer, 3, 0.9)
    _told(rp, peer, 3, 0.3)
    told = _score(rp, peer, told=0.3)
    assert rp._own_count(peer) == 3
    assert rp.reputations.brought[str(peer)] > TIER1_CAP
    assert rp._bounded(peer, told) == rp.reputations.brought[str(peer)]


def test_a_probe_half_is_not_own_evidence_without_the_policy():
    rp, peer = _rp(JoinPolicy()), uuid4()
    _probe(rp, peer, 3)
    assert rp._own_evidence(peer) == []


def test_brought_reads_our_scores_not_the_peers():
    """The peer rating us 1.0 does not raise its brought score (the CTFT side
    fix): our 0.3 of it is what counts."""
    rp, peer = _rp(), uuid4()
    for _ in range(3):
        _pair(rp, rp.identity.uuid, 0.3, peer, 1.0)
    _score(rp, peer)
    assert rp.reputations.brought[str(peer)] == pytest.approx(0.3)


def test_policy_off_keeps_no_brought_and_reads_told():
    rp, peer = _rp(JoinPolicy()), uuid4()
    _own(rp, peer, 3)
    _told(rp, peer, 3, 0.95)
    told = _score(rp, peer, told=0.95, coop=True)
    assert rp.reputations.brought == {}
    assert rp._bounded(peer, told) == told
    assert rp._exclusion_score(peer, told) == told


def test_told_alone_never_excludes():
    rp, peer = _rp(), uuid4()
    _told(rp, peer, 3, 0.0)
    told = _score(rp, peer, told=0.95, coop=True)
    assert rp._is_excluded(told)
    assert rp._exclusion_score(peer, told) is None
    net = queue.Queue()
    rp._publish_tier_change({'network': net, 'identity': queue.Queue(),
                             'negotiation': queue.Queue()}, peer, told)
    assert str(peer) not in rp._excluded


def test_brought_below_the_cutoff_excludes():
    rp, peer = _rp(), uuid4()
    _own(rp, peer, 3, 0.0)
    told = _score(rp, peer)
    assert rp._is_excluded(rp._exclusion_score(peer, told))


def test_a_slash_floors_both_maps_and_excludes():
    rp, peer = _rp(), uuid4()
    _own(rp, peer, 3, 0.9)
    _score(rp, peer)
    rp._slashed[str(peer)] = (0.05, 1)
    told = _score(rp, peer)
    assert told == pytest.approx(0.05)
    assert rp.reputations.brought[str(peer)] == pytest.approx(0.05)
    assert rp._is_excluded(rp._exclusion_score(peer, told))


def test_the_prior_skips_told_entries_only_under_the_policy():
    rp, peer = _rp(), uuid4()
    _told(rp, peer, 3, 0.9)
    rp._catchup_marks = {'': {tx.index for tx in rp.history}}
    assert rp._prereputation_prior(peer) == pytest.approx(rp.PREREP_NEUTRAL)
    rp.join_policy = JoinPolicy()
    assert rp._prereputation_prior(peer) > rp.PREREP_NEUTRAL


def test_a_seed_replaces_a_told_only_score():
    rp, peer = _rp(), uuid4()
    rp.reputations.update(peer, 0.4)
    rp._offer_seed('test', peer, 0.3, 'contact')
    assert rp.reputations[peer] == pytest.approx(0.3)
    assert rp.reputations.brought[str(peer)] == pytest.approx(0.3)


@pytest.mark.parametrize('why', ['earned', 'warm', 'slashed'])
def test_a_seed_never_overrides_earned_warm_or_slashed(why):
    rp, peer = _rp(), uuid4()
    rp.reputations.update(peer, 0.4)
    if why == 'earned':
        _own(rp, peer, 1)
    elif why == 'warm':
        rp._warm_started = {str(peer)}
    else:
        rp._slashed[str(peer)] = (0.05, 1)
    rp._offer_seed('test', peer, 0.3, 'contact')
    assert rp.reputations[peer] == pytest.approx(0.4)
    assert (str(peer) in rp.reputations.brought) == (why != 'slashed')


def test_without_the_policy_a_held_score_blocks_the_seed():
    rp, peer = _rp(JoinPolicy()), uuid4()
    rp.reputations.update(peer, 0.4)
    rp._offer_seed('test', peer, 0.3, 'contact')
    assert rp.reputations[peer] == pytest.approx(0.4)
    assert rp.reputations.brought == {}


def test_a_rep_resp_answers_bounded():
    rp, peer = _rp(), uuid4()
    _told(rp, peer, 3, 0.95)
    rp.reputations.update(peer, 0.95)
    rp._coop_mode[peer] = True
    rp._compute_reputation(peer, 'proc', None, respond=True)
    rep = rp.requested_reps[-1][0]
    assert rep.score == pytest.approx(TIER1_CAP, abs=1e-6)


def test_brought_persists_beside_current():
    reps = Reputations({uuid4(): 0.9}, brought={'a': 0.8})
    doc = reps.to_dict()
    assert doc['brought'] == {'a': 0.8}
    assert Reputations(**doc).brought == {'a': 0.8}
    assert 'brought' not in Reputations({uuid4(): 0.9}).to_dict()


def test_an_anchored_set_reaches_the_protocol():
    import logging
    proto = Protocol('reputation', logging.getLogger('test'), None)
    assert proto.anchored == frozenset()
    proto.run_message_handlers({'x': None}, AnchoredSet(['a', 'b']))
    assert proto.anchored == {'a', 'b'}


def test_an_anchoring_change_makes_the_peer_due():
    rp, peer = _rp(), uuid4()
    rp._rescore_due.clear()
    rp.protocol.anchored = frozenset({str(peer)})
    rp._note_anchors()
    assert str(peer) in rp._rescore_due
    rp._rescore_due.clear()
    rp._note_anchors()
    assert not rp._rescore_due


def test_identity_publishes_anchors_on_change_only():
    from autonomous_trust.core._python.identity.peers import Peers
    from tests.a_unit.test_late_joiner_caps_resync import (_build_process,
                                                           _new_identity)
    me, a, b = (_new_identity(n, '10.0.0.%d' % i)
                for i, n in enumerate(('me', 'a', 'b'), 1))
    peers = Peers()
    peers.add(a)
    peers.add(b)
    proc = _build_process(me, peers)
    proc.join_policy = ON
    anchors = {str(a.uuid)}
    proc.is_anchored = lambda ident: str(ident.uuid) in anchors
    sent = []
    proc.update = lambda msg, queues: sent.append(msg)
    proc._publish_anchors({})
    proc._publish_anchors({})
    assert [m.uuids for m in sent] == [{str(a.uuid)}]
    anchors.add(str(b.uuid))
    proc._publish_anchors({})
    assert sent[-1].uuids == {str(a.uuid), str(b.uuid)}
    proc.join_policy = JoinPolicy()
    proc._publish_anchors({})
    assert len(sent) == 2


# --- The join burst's counts (Phase 5) --------------------------------------

def _roster(rp, *peers):
    from types import SimpleNamespace
    rp.protocol.peers = SimpleNamespace(all=[SimpleNamespace(uuid=p) for p in peers])


def _published(rp):
    q = queue.Queue()
    rp._last_counts_pass = None
    rp._publish_probe_counts({rp.BOOTSTRAP_WORKER_QUEUE: q}, 0.0)
    return [q.get_nowait().counts for _ in range(q.qsize())]


def test_the_burst_count_is_probe_verdicts_while_bounded():
    rp, peer = _rp(), uuid4()
    assert rp._burst_count(peer) == 0
    _probe(rp, peer, 1)
    _own(rp, peer, 1)
    assert rp._burst_count(peer) == 1
    _probe(rp, peer, 1)
    assert rp._burst_count(peer) is None          # graduated: 3 own entries


def test_an_anchored_or_slashed_peer_is_no_target():
    rp, a, b = _rp(), uuid4(), uuid4()
    rp.protocol.anchored = frozenset({str(a)})
    rp._slashed[str(b)] = (0.05, 1)
    assert rp._burst_count(a) is None
    assert rp._burst_count(b) is None


def test_counts_publish_the_roster_on_change_only():
    rp, a, b = _rp(), uuid4(), uuid4()
    _roster(rp, a, b, rp.identity.uuid)
    assert _published(rp) == [{str(a): 0, str(b): 0}]
    assert _published(rp) == []
    _probe(rp, a, 1)
    rp._note_interaction(a)
    assert _published(rp) == [{str(a): 1, str(b): 0}]
    _probe(rp, a, 2)
    rp._note_interaction(a)
    assert _published(rp) == [{str(b): 0}]        # a graduated
    _roster(rp, a)
    assert _published(rp) == [{}]                 # b left the roster


def test_an_anchoring_change_recounts():
    rp, a = _rp(), uuid4()
    _roster(rp, a)
    assert _published(rp) == [{str(a): 0}]
    rp.protocol.anchored = frozenset({str(a)})
    rp._note_anchors()
    assert _published(rp) == [{}]


def test_counts_are_throttled_and_retried_when_refused():
    rp, a = _rp(), uuid4()
    _roster(rp, a)
    full = queue.Queue(maxsize=1)
    full.put('busy')
    rp.q_cadence = 0.01
    rp._publish_probe_counts({rp.BOOTSTRAP_WORKER_QUEUE: full}, 10.0)
    assert full.get_nowait() == 'busy'
    rp._publish_probe_counts({rp.BOOTSTRAP_WORKER_QUEUE: full}, 10.5)
    assert full.empty()                           # throttled
    rp._publish_probe_counts({rp.BOOTSTRAP_WORKER_QUEUE: full}, 11.0)
    assert full.get_nowait().counts == {str(a): 0}


def test_no_counts_without_the_policy():
    rp, a = _rp(JoinPolicy()), uuid4()
    _roster(rp, a)
    assert _published(rp) == []
