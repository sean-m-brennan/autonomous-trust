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
"""Entering the cooperation regime: own evidence wins.

Hostile-join runs without the policy, 2026-11-04: contrite tit-for-tat over a
joiner's own transactions scored its contact 0.84, above COOP_ENTER, so the
next rescore took the cooperation mean over everyone's entries; the cohort's
slander made that 0.34, below COOP_EXIT, so the rescore after went back. The
tier flipped every minute. A peer now enters cooperation only if the
cooperation score would itself be at or above COOP_EXIT, and leaves it in the
same rescore that score falls below; otherwise it stays in tit-for-tat. The
same rule holds for the brought score. The C twin is
src/c/test/rep_coop_entry_test.c.
"""
import pytest

from autonomous_trust.core._python.identity.join_policy import INERT as JOIN_POLICY_INERT
from autonomous_trust.core._python.reputation.repprocess import _brought_of
from tests.a_unit.test_brought_told import (  # noqa: F401 (fixture)
    _cfg_dir, _rp, _pair, _own, _told, _score, ON)

CTFT_10 = (10 * 0.9 + 3 * 0.2) / 13


def _rescore(rp, peer, times):
    out = []
    for _ in range(times):
        rp._compute_reputation(peer, None, None, respond=False)
        out.append(rp.reputations[peer])
    return out


def test_a_slandered_mean_does_not_pull_a_peer_into_cooperation():
    rp = _rp(JOIN_POLICY_INERT)
    peer = rp.identity.uuid.__class__(int=7)
    _own(rp, peer, 10)
    _told(rp, peer, 30, score=0.1)
    assert rp._pure_reputation(peer) < rp.COOP_EXIT
    assert _rescore(rp, peer, 5) == [pytest.approx(CTFT_10)] * 5
    assert rp._coop_mode[peer] is False


def test_a_mean_that_holds_enters_cooperation():
    rp = _rp(JOIN_POLICY_INERT)
    peer = rp.identity.uuid.__class__(int=7)
    _own(rp, peer, 10)
    _told(rp, peer, 30, score=0.9)
    got = _rescore(rp, peer, 2)
    assert got[-1] == pytest.approx(rp._pure_reputation(peer))
    assert rp._coop_mode[peer] is True


def test_a_peer_whose_mean_falls_leaves_in_that_rescore():
    rp = _rp(JOIN_POLICY_INERT)
    peer = rp.identity.uuid.__class__(int=7)
    _own(rp, peer, 10)
    _told(rp, peer, 30, score=0.1)
    rp.reputations.update(peer, 0.8)
    rp._coop_mode[peer] = True
    # The hostile-join runs of 2026-11-05 scored the contact once on the
    # slandered mean on the way out, and lost its tier for a minute.
    assert _rescore(rp, peer, 5) == [pytest.approx(CTFT_10)] * 5
    assert rp._coop_mode[peer] is False


def test_a_peer_whose_mean_holds_stays_in_cooperation():
    rp = _rp(JOIN_POLICY_INERT)
    peer = rp.identity.uuid.__class__(int=7)
    _own(rp, peer, 10)
    _told(rp, peer, 30, score=0.9)
    rp.reputations.update(peer, 0.8)
    rp._coop_mode[peer] = True
    pure = rp._pure_reputation(peer)
    assert _rescore(rp, peer, 3) == [pytest.approx(pure)] * 3
    assert rp._coop_mode[peer] is True


def test_the_brought_score_follows_the_same_rule():
    rp = _rp(ON)
    peer = rp.identity.uuid.__class__(int=7)
    _own(rp, peer, 10)
    # Two heavy entries we scored low: the task-weighted mean of our scores
    # falls below the exit while contrite tit-for-tat stays above the entry.
    for _ in range(2):
        task = _pair(rp, rp.identity.uuid, 0.1, peer, 0.9)
        rp.task_weights[str(task)] = 100
    ctft = (10 * 0.9 + 2 * 0.1 + 3 * 0.2) / 15
    assert ctft > rp.COOP_ENTER
    brought = []
    for _ in range(5):
        rp._compute_reputation(peer, None, None, respond=False)
        brought.append(_brought_of(rp)[str(peer)])
    assert brought == [pytest.approx(ctft)] * 5
    assert rp._coop_brought[str(peer)] is False
