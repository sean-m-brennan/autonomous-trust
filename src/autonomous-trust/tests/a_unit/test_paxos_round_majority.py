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
"""A Paxos round's bar and its ballots (doc/architecture/reputation.md,
"Agreeing on a history").

A round carries, in both phases, on a strict majority of the group counting
the proposer: N // 2 of the others. It used to need one member MORE than a
majority to commit (all three of three, four of five), so one stopped member
of three blocked every commit, and one member LESS to be granted in an even
group (two of four). A member's grant or acceptance counts once per round,
and an acceptor takes no transaction from a ballot below one it has promised
since.
"""
import queue
from types import SimpleNamespace
from uuid import uuid4

import pytest

from autonomous_trust.core.config import from_json_string
from autonomous_trust.core.reputation.protocol import ReputationProtocol
from autonomous_trust.core.reputation.reputation import TransactionScore

from tests.a_unit.test_commit_certificates import (_ident, _node, _sent, _msg,
                                                    _roster)


def _group(n):
    return tuple(_ident('m%d' % i, i + 1) for i in range(n))


def _committed(q):
    return [m for m in _sent(q) if m.function == ReputationProtocol.committed]


@pytest.mark.parametrize('n, others', [(1, 0), (2, 1), (3, 1), (4, 2), (5, 2),
                                        (6, 3), (7, 3)])
def test_a_round_needs_half_the_others(n, others):
    members = _group(n)
    rp, _ = _node(members[0], _roster(members[0], members), required=False)
    assert rp._round_quorum(None) == others


def _proposer(members):
    p = members[0]
    rp, q = _node(p, _roster(p, members), required=False)
    score = TransactionScore(uuid4(), 0.9)
    rp.proposals[(7, 1)] = score
    return rp, q, score


def _accept(rp, q, voter, idx=(7, 1)):
    rp.handle_accepted(q, _msg(ReputationProtocol.accepted,
                               (idx[0], idx[1], rp.identity.uuid), voter))


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


def _grant(rp, q, granter, idx=(1, 1), verified=True):
    m = _msg(ReputationProtocol.grant,
             ((idx[0], idx[1], rp.identity.uuid), (None, 0), None), granter)
    m.verified = verified
    rp.handle_grant(q, m)


def _transactions(q):
    return [m for m in _sent(q) if m.function == ReputationProtocol.transaction]


class TestGrantBar:
    @pytest.mark.parametrize('n, grants', [(3, 1), (4, 2), (5, 2)])
    def test_the_transaction_goes_out_at_a_majority(self, n, grants):
        members = _group(n)
        p = members[0]
        rp, q = _node(p, _roster(p, members), required=False)
        score = TransactionScore(uuid4(), 0.9)
        rp.my_requests[(1, 1)] = SimpleNamespace(score=score, count=0)
        for i in range(grants):
            assert not _transactions(q)
            _grant(rp, q, members[i + 1])
        assert len(_transactions(q)) == 1

    def test_a_member_grants_once(self):
        members = _group(5)
        p = members[0]
        rp, q = _node(p, _roster(p, members), required=False)
        rp.my_requests[(1, 1)] = SimpleNamespace(
            score=TransactionScore(uuid4(), 0.9), count=0)
        _grant(rp, q, members[1])
        _grant(rp, q, members[1])
        assert not _transactions(q)
        _grant(rp, q, members[2])
        assert len(_transactions(q)) == 1

    def test_an_unverified_grant_is_not_counted(self):
        members = _group(3)
        p = members[0]
        rp, q = _node(p, _roster(p, members), required=False)
        rp.my_requests[(1, 1)] = SimpleNamespace(
            score=TransactionScore(uuid4(), 0.9), count=0)
        _grant(rp, q, members[1], verified=False)
        assert not _transactions(q)

    def test_the_proposer_outranks_every_ballot_it_promised(self):
        members = _group(3)
        rp, q = _node(members[0], _roster(members[0], members), required=False)
        rp.last_id = 10 ** 15   # a rival's ballot from a clock far ahead
        rp._start_paxos(q, TransactionScore(uuid4(), 0.9))
        (idx,) = rp.my_requests
        assert idx[0] == 10 ** 15 + 1 and rp.last_id == idx[0]


def _acceptor(members):
    a = members[1]
    rp, q = _node(a, _roster(a, members), required=False)
    return rp, q


def _propose(rp, q, proposer, id1, slot=1, task=None):
    if (id1, slot) not in rp.requests:
        rp.requests.append((id1, slot))
    if rp.last_id is None or rp.last_id < id1:
        rp.last_id = id1        # the grant's promise
    score = TransactionScore(task or uuid4(), 0.9)
    rp.handle_transaction(q, _msg(ReputationProtocol.transaction,
                                  ((id1, slot, proposer.uuid), score),
                                  proposer))
    return [m for m in _sent(q) if m.function == ReputationProtocol.accepted]


class TestAcceptorBallots:
    def test_the_granted_ballot_is_accepted(self):
        members = _group(3)
        rp, q = _acceptor(members)
        assert len(_propose(rp, q, members[0], 100)) == 1

    def test_a_ballot_below_a_later_promise_is_refused(self):
        members = _group(3)
        rp, q = _acceptor(members)
        rp.requests.append((100, 1))
        rp.last_id = 200            # promised a rival's higher ballot since
        assert _propose(rp, q, members[0], 100) == []

    def test_two_halves_at_one_slot_are_both_accepted(self):
        """The slot is not a write index: halves merge by task, so two
        different halves granted at one id2 are not rivals."""
        members = _group(3)
        rp, q = _acceptor(members)
        assert len(_propose(rp, q, members[0], 100)) == 1
        assert len(_propose(rp, q, members[2], 200)) == 1

    def test_an_ungranted_ballot_is_refused(self):
        members = _group(3)
        rp, q = _acceptor(members)
        rp.last_id = 100
        score = TransactionScore(uuid4(), 0.9)
        rp.handle_transaction(q, _msg(ReputationProtocol.transaction,
                                      ((100, 1, members[0].uuid), score),
                                      members[0]))
        assert not [m for m in _sent(q)
                    if m.function == ReputationProtocol.accepted]


class TestRoundExpiry:
    def test_rounds_older_than_the_expiration_are_dropped(self):
        """id1 is in milliseconds and the clock in seconds (ISSUES §2.66)."""
        members = _group(3)
        rp, q = _acceptor(members)
        import time
        now_ms = int(time.time() * 1000)
        old, new = now_ms - (rp.expiration + 5) * 1000, now_ms
        rp.requests[:] = [(old, 1), (new, 1)]
        rp.proposals.update({(old, 1): 1, (new, 1): 2})
        rp.grants.update({(old, 1): set(), (new, 1): set()})
        rp.acceptances.update({(old, 1): set(), (new, 1): set()})
        rp._expire_rounds(time.time())
        assert rp.requests == [(new, 1)]
        for rounds in (rp.proposals, rp.grants, rp.acceptances):
            assert list(rounds) == [(new, 1)]
