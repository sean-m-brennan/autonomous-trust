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
"""A half's co-signing bar (doc/architecture/reputation.md, "Agreeing on an
order").

A half carries on a strict majority of the group counting the proposer:
N // 2 of the others, each acceptance signed over the half's
commit_designation. It used to need one member MORE than a majority (all
three of three, four of five), so one stopped member of three blocked every
commit. A member's acceptance counts once per round.
"""
import queue
from types import SimpleNamespace
from uuid import uuid4

import pytest

from autonomous_trust.core.config import from_json_string
from autonomous_trust.core.reputation.protocol import ReputationProtocol
from autonomous_trust.core.reputation.reputation import TransactionScore

from tests.a_unit.test_commit_certificates import (_ident, _node, _sent, _msg,
                                                    _roster, _sign)


def _group(n):
    return tuple(_ident('m%d' % i, i + 1) for i in range(n))


def _committed(q):
    return [m for m in _sent(q) if m.function == ReputationProtocol.committed]


@pytest.mark.parametrize('n, others', [(1, 0), (2, 1), (3, 1), (4, 2), (5, 2),
                                        (6, 3), (7, 3)])
def test_a_round_needs_half_the_others(n, others):
    members = _group(n)
    rp, _ = _node(members[0], _roster(members[0], members))
    assert rp._round_quorum(None) == others


def _proposer(members):
    p = members[0]
    rp, q = _node(p, _roster(p, members))
    score = TransactionScore(uuid4(), 0.9)
    rp.proposals[(7, 1)] = score
    return rp, q, score


def _accept(rp, q, voter, idx=(7, 1)):
    """`voter` accepts round `idx`, signing the half it carries (any half,
    for a round the proposer never ran)."""
    score = rp.proposals.get(idx) or TransactionScore(uuid4(), 0.9)
    sig = _sign(voter, rp.identity, score.task_id, score.score)
    rp.handle_accepted(q, _msg(ReputationProtocol.accepted,
                               (idx[0], idx[1], rp.identity.uuid, sig), voter))


class TestCommitBar:
    def test_two_of_three_commit(self):
        members = _group(3)
        rp, q, score = _proposer(members)
        _accept(rp, q, members[1])
        assert len(_committed(q)) == 1

    def test_three_of_five_commit(self):
        members = _group(5)
        rp, q, score = _proposer(members)
        _accept(rp, q, members[1])
        assert not _committed(q)
        _accept(rp, q, members[2])
        assert len(_committed(q)) == 1

    def test_a_member_counts_once(self):
        members = _group(5)
        rp, q, score = _proposer(members)
        _accept(rp, q, members[1])
        _accept(rp, q, members[1])
        assert not _committed(q)

    def test_an_acceptance_counts_only_for_its_own_round(self):
        """A re-proposal of the same half is a new round: what the first
        round collected does not carry over."""
        members = _group(5)
        rp, q, score = _proposer(members)
        rp.proposals[(8, 1)] = score
        _accept(rp, q, members[1], idx=(7, 1))
        _accept(rp, q, members[2], idx=(8, 1))
        assert not _committed(q)

    def test_an_acceptance_for_an_unknown_round_is_dropped(self):
        members = _group(3)
        rp, q, score = _proposer(members)
        _accept(rp, q, members[1], idx=(9, 1))
        assert not _committed(q)


class TestRoundExpiry:
    def test_rounds_older_than_the_expiration_are_dropped(self):
        """id1 is in milliseconds and the clock in seconds (ISSUES §2.66)."""
        members = _group(3)
        rp, q = _node(members[0], _roster(members[0], members))
        import time
        now_ms = int(time.time() * 1000)
        old, new = now_ms - (rp.expiration + 5) * 1000, now_ms
        rp.proposals.update({(old, 1): 1, (new, 1): 2})
        rp.acceptances.update({(old, 1): set(), (new, 1): set()})
        rp._expire_rounds(time.time())
        for rounds in (rp.proposals, rp.acceptances):
            assert list(rounds) == [(new, 1)]
