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
"""The rescore sweep: what rates a peer in a running node (Phase 4 P4.1).

A rep_req used to be the only thing that computed and stored a score, and a
running node sends none outside task automation, so moderation_cohort.sh found
every peer still unrated after eleven commits. These assert what the sweep
QUEUES for publication, because an unpublished tier was the defect. Mirrors
the C twin, test/rescore_sweep_test.c.
"""
from types import SimpleNamespace
from uuid import uuid4

from autonomous_trust.core._python.identity.peer_standing import (
    PeerStanding, STANDING_CAPPED, STANDING_SOURCE_ETHNE)
from .test_peer_standing import _make_rep_process, _stand

T0 = 1_000_000.0


def _with_peer(rp, peer):
    rp.peers.all = [SimpleNamespace(uuid=str(peer))]


def _published(rp):
    return [str(u) for u, _ in rp.pending_tiers]


def test_an_unscored_peer_is_rated_at_its_prior_and_published():
    rp = _make_rep_process()
    peer = uuid4()
    _with_peer(rp, peer)
    assert rp._rescore_sweep(T0) == 1
    assert _published(rp) == [str(peer)]
    assert rp.requested_reps == []          # nobody asked: no rep_resp
    score = rp.reputations.current[str(peer)]
    assert abs(score - rp.PREREP_NEUTRAL) < 1e-9


def test_a_rated_peer_is_rescored_only_when_its_chain_moved():
    rp = _make_rep_process()
    peer = uuid4()
    _with_peer(rp, peer)
    rp.reputations.update(str(peer), 0.9)
    assert rp._rescore_sweep(T0) == 1           # first: identity is told
    rp._publish_tier_change({}, str(peer), rp.reputations.current[str(peer)])
    rp.pending_tiers.clear()
    assert rp._rescore_sweep(T0 + 1800) == 0
    rp._note_interaction(peer)
    assert rp._rescore_sweep(T0 + 3600) == 1
    assert _published(rp) == [str(peer)]
    assert rp._rescore_sweep(T0 + 7200) == 0   # the mark is spent


def test_a_restored_peer_is_told_to_identity_once():
    """A restart keeps the score (snapshot) and loses identity's tiers
    (memory). Without this the restored peer is rated, never due, and gated
    at tier 0 until his tier changes. Mirrors the C twin."""
    rp = _make_rep_process()
    peer = uuid4()
    _with_peer(rp, peer)
    rp.reputations.update(str(peer), 0.7)       # the warm start
    assert rp._rescore_sweep(T0) == 1
    assert _published(rp) == [str(peer)]
    # The process loop's drain is what records the tier as told.
    for u, sc in list(rp.pending_tiers):
        rp._publish_tier_change({}, u, sc)
    rp.pending_tiers.clear()
    assert rp._rescore_sweep(T0 + 3600) == 0


def test_the_sweep_is_throttled():
    rp = _make_rep_process()
    peer = uuid4()
    _with_peer(rp, peer)
    rp.reputations.update(str(peer), 0.9)
    assert rp._rescore_sweep(T0) == 1           # first: identity is told
    rp._note_interaction(peer)
    assert rp._rescore_sweep(T0 + 1) == 0      # inside AT_REP_RESCORE_SEC
    assert rp._rescore_sweep(T0 + 3600) == 1   # the mark waited


def test_a_node_never_scores_itself():
    rp = _make_rep_process()
    rp._rescore_due.add(str(rp.identity.uuid))
    assert rp._rescore_sweep(T0) == 0
    assert rp.pending_tiers == []


def test_a_standing_bounds_what_the_sweep_writes():
    rp = _make_rep_process()
    peer = uuid4()
    _with_peer(rp, peer)
    _stand(rp, str(peer), STANDING_CAPPED, 0.10, source=STANDING_SOURCE_ETHNE)
    assert rp._rescore_sweep(T0) == 1
    assert abs(rp.reputations.current[str(peer)] - 0.10) < 1e-9


def test_a_tier_update_lost_to_a_full_queue_is_published_again():
    """Moderation cohort mod-2505620 (2026-09-23): the publication record was
    written before the send, so a tier_update lost to a full identity queue
    was never repeated and identity's gate held a stale tier. Mirrors the C
    twin."""
    from queue import Full
    from autonomous_trust.core._python.system import CfgIds

    class _FullQueue:
        def put(self, *a, **k):
            raise Full

    rp = _make_rep_process()
    peer = uuid4()
    _with_peer(rp, peer)
    rp.reputations.update(str(peer), 0.7)       # the warm start
    assert rp._rescore_sweep(T0) == 1
    for u, sc in list(rp.pending_tiers):
        rp._publish_tier_change({CfgIds.identity: _FullQueue()}, u, sc)
    rp.pending_tiers.clear()
    assert str(peer) not in rp.peer_tiers       # not recorded as told
    assert rp._rescore_sweep(T0 + 3600) == 1    # so the next sweep retries
    assert _published(rp) == [str(peer)]
