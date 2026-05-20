# ******************
#  Copyright 2025 Sean M. Brennan and contributors
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
import pytest
from types import SimpleNamespace
from uuid import uuid4

from autonomous_trust.core.reputation.reputation import (
    TransactionScore, Transaction, TransactionHistory,
    Reputation, Reputations,
)
from autonomous_trust.core.reputation.repprocess import ReputationProcess


class TestTransactionScore:
    def test_init(self):
        ts = TransactionScore(task_id=uuid4(), score=0.9)
        assert ts.score == 0.9


class TestTransaction:
    def test_len_empty(self):
        tx = Transaction(task_id=uuid4())
        assert len(tx) == 0

    def test_len_one(self):
        tx = Transaction(task_id=uuid4(), p1_id=uuid4(), p1_score=0.5)
        assert len(tx) == 1

    def test_len_two(self):
        tx = Transaction(task_id=uuid4(), p1_id=uuid4(), p1_score=0.5,
                         p2_id=uuid4(), p2_score=0.8)
        assert len(tx) == 2

    def test_add_first(self):
        tx = Transaction(task_id=uuid4())
        pid = uuid4()
        tx.add(pid, 0.7)
        assert tx.p1_id == pid
        assert tx.p1_score == 0.7
        assert len(tx) == 1

    def test_add_second(self):
        tx = Transaction(task_id=uuid4())
        p1, p2 = uuid4(), uuid4()
        tx.add(p1, 0.7)
        tx.add(p2, 0.9)
        assert tx.p2_id == p2
        assert tx.p2_score == 0.9
        assert len(tx) == 2


class TestTransactionHistory:
    def test_empty_init(self):
        th = TransactionHistory()
        assert len(th) == 0

    def test_update_creates_transaction(self):
        th = TransactionHistory()
        tid = uuid4()
        p1, p2 = uuid4(), uuid4()
        th.update(tid, p1, 0.8)
        th.update(tid, p2, 0.9)
        assert len(th) == 1
        assert th[tid].p1_id == p1
        assert th[tid].p2_id == p2

    def test_update_ignores_duplicate(self):
        th = TransactionHistory()
        tid = uuid4()
        p1, p2, p3 = uuid4(), uuid4(), uuid4()
        th.update(tid, p1, 0.8)
        th.update(tid, p2, 0.9)
        th.update(tid, p3, 0.5)  # ignored since already 2 participants
        assert th[tid].p2_id == p2  # unchanged

    def test_by_peer(self):
        th = TransactionHistory()
        tid = uuid4()
        p1, p2 = uuid4(), uuid4()
        th.update(tid, p1, 0.8)
        th.update(tid, p2, 0.9)
        assert len(th.by_peer(p1)) >= 1

    def test_era(self):
        th = TransactionHistory()
        for _ in range(3):
            tid = uuid4()
            th.update(tid, uuid4(), 0.5)
            th.update(tid, uuid4(), 0.6)
        chain = th.era(1)
        assert len(chain) == 2

    def test_catchup(self):
        th = TransactionHistory()
        tid = uuid4()
        p1, p2 = uuid4(), uuid4()
        chain = [Transaction(tid, p1, 0.8, p2, 0.9, index=5)]
        th.catchup(chain)
        # catchup checks if index > len(chain), so with empty chain and index=5, it adds
        assert len(th) == 1

    def test_init_with_chain(self):
        tid = uuid4()
        p1, p2 = uuid4(), uuid4()
        tx = Transaction(tid, p1, 0.8, p2, 0.9, index=0)
        th = TransactionHistory(_chain=[tx])
        assert len(th) == 1
        assert th[tid] is tx


class TestReputation:
    def test_init(self):
        pid = uuid4()
        r = Reputation(peer_id=pid, score=0.95)
        assert r.peer_id == pid
        assert r.score == 0.95


class TestReputations:
    def test_empty_init(self):
        r = Reputations()
        assert uuid4() not in r

    def test_update_and_get(self):
        r = Reputations()
        pid = uuid4()
        r.update(pid, 0.88)
        assert pid in r
        assert r[pid] == 0.88

    def test_update_overwrite(self):
        r = Reputations()
        pid = uuid4()
        r.update(pid, 0.5)
        r.update(pid, 0.9)
        assert r[pid] == 0.9

    def test_init_with_data(self):
        pid = uuid4()
        r = Reputations(current={pid: 0.7})
        assert r[pid] == 0.7


# Algorithm pins for ReputationProcess._contrite_tit_for_tat and
# ._pure_reputation.  These mirror the C unit tests in
# src/c/test/reputation3_test.c (test_reputation_contrite_tft,
# test_reputation_pure_with_counterparty) using identical input shapes
# and expected outputs, so cross-language divergence in the algorithm
# fails one side's tests immediately.  Documented in
# doc/architecture/reputation.md:71-83.

def _stub_proc(self_uuid, reputations=None):
    """Build the minimal SimpleNamespace that _contrite_tit_for_tat /
    _pure_reputation read off ``self``: history, identity, reputations,
    logger.  Constructing a real ReputationProcess pulls in queues,
    keys, and a temp config dir we don't need here."""
    stub = SimpleNamespace()
    stub.history = TransactionHistory()
    stub.identity = SimpleNamespace(uuid=self_uuid)
    stub.reputations = reputations or Reputations()
    stub.logger = SimpleNamespace(debug=lambda *a, **k: None)
    return stub


class TestContriteTitForTat:
    def test_empty_history_returns_0_49(self):
        self_id, peer_id = uuid4(), uuid4()
        stub = _stub_proc(self_id)
        peer = SimpleNamespace(uuid=peer_id)
        assert ReputationProcess._contrite_tit_for_tat(stub, peer) == 0.49

    def test_cooperative_self_p1(self):
        """Self enters as p1, peer as p2, both cooperate. Falls into
        the cooperate branch → max(0.51, peer_standing) = 0.8."""
        self_id, peer_id, task = uuid4(), uuid4(), uuid4()
        stub = _stub_proc(self_id)
        stub.history.update(task, self_id, 0.9)  # self → p1
        stub.history.update(task, peer_id, 0.8)  # peer → p2
        score = ReputationProcess._contrite_tit_for_tat(
            stub, SimpleNamespace(uuid=peer_id))
        assert score == pytest.approx(0.8, abs=0.001)

    def test_cooperative_self_p2(self):
        """Peer enters as p1, self as p2.  Same expected output — the
        algorithm must be order-symmetric in which side filled p1
        first.  This is the exact case the previous swap bug
        regressed."""
        self_id, peer_id, task = uuid4(), uuid4(), uuid4()
        stub = _stub_proc(self_id)
        stub.history.update(task, peer_id, 0.8)  # peer → p1
        stub.history.update(task, self_id, 0.9)  # self → p2
        score = ReputationProcess._contrite_tit_for_tat(
            stub, SimpleNamespace(uuid=peer_id))
        assert score == pytest.approx(0.8, abs=0.001)

    def test_retaliation_branch(self):
        """Peer defected on last tx (0.2) and self's standing is good
        (mean 0.9) → retaliation branch → min(0.49, peer_standing) =
        0.2."""
        self_id, peer_id = uuid4(), uuid4()
        stub = _stub_proc(self_id)
        t1, t2 = uuid4(), uuid4()
        stub.history.update(t1, self_id, 0.9)
        stub.history.update(t1, peer_id, 0.8)  # peer cooperated once
        stub.history.update(t2, self_id, 0.9)
        stub.history.update(t2, peer_id, 0.2)  # peer defects, peer_last
        score = ReputationProcess._contrite_tit_for_tat(
            stub, SimpleNamespace(uuid=peer_id))
        # peer_standing = (0.8 + 0.2) / 2 = 0.5; my_standing = 0.9.
        # peer_last < 0.5, my_standing >= 0.5 → min(0.49, 0.5) = 0.49.
        assert score == pytest.approx(0.49, abs=0.001)

    def test_contrition_branch(self):
        """Peer defected on last tx but my standing is also poor →
        contrition branch → max(0.51, peer_standing)."""
        self_id, peer_id = uuid4(), uuid4()
        stub = _stub_proc(self_id)
        t1, t2 = uuid4(), uuid4()
        stub.history.update(t1, self_id, 0.2)   # self defected too
        stub.history.update(t1, peer_id, 0.3)
        stub.history.update(t2, self_id, 0.2)
        stub.history.update(t2, peer_id, 0.4)   # peer_last < 0.5
        score = ReputationProcess._contrite_tit_for_tat(
            stub, SimpleNamespace(uuid=peer_id))
        # peer_standing = (0.3 + 0.4) / 2 = 0.35; my_standing = 0.2
        # peer_last < 0.5, my_standing < 0.5 → max(0.51, 0.35) = 0.51.
        assert score == pytest.approx(0.51, abs=0.001)

    def test_third_party_transactions_ignored(self):
        """Transactions involving peer but not self should not enter
        the bilateral computation."""
        self_id, peer_id, other = uuid4(), uuid4(), uuid4()
        stub = _stub_proc(self_id)
        # peer ↔ other (no self involvement) — must be ignored.
        t = uuid4()
        stub.history.update(t, peer_id, 0.1)
        stub.history.update(t, other, 0.1)
        score = ReputationProcess._contrite_tit_for_tat(
            stub, SimpleNamespace(uuid=peer_id))
        # No bilateral self↔peer history → no-history default 0.49.
        assert score == 0.49


class TestPureReputation:
    def test_empty_history_returns_0_5(self):
        """Default 0.5 (mirrors reputation.c:419-420 / :454-455).
        Returning 0.0 would route the peer right back into CTFT mode."""
        self_id, peer_id = uuid4(), uuid4()
        stub = _stub_proc(self_id)
        score = ReputationProcess._pure_reputation(
            stub, SimpleNamespace(uuid=peer_id))
        assert score == 0.5

    def test_weighted_average(self):
        """Counterparty score weighted by counterparty reputation."""
        self_id, peer_id = uuid4(), uuid4()
        reps = Reputations()
        reps.update(self_id, 0.8)
        stub = _stub_proc(self_id, reputations=reps)
        t = uuid4()
        stub.history.update(t, peer_id, 0.9)   # peer is p1
        stub.history.update(t, self_id, 0.7)   # self is p2 (counterparty)
        score = ReputationProcess._pure_reputation(
            stub, SimpleNamespace(uuid=peer_id))
        # counterparty_score = 0.7, cp_rep = 0.8 → 0.56.
        assert score == pytest.approx(0.56, abs=0.001)

    def test_unknown_counterparty_uses_default_0_5(self):
        """Counterparty missing from self.reputations falls back to
        0.5 (mirrors C); does not silently skip the transaction."""
        self_id, peer_id = uuid4(), uuid4()
        stub = _stub_proc(self_id)  # empty reputations dict
        t = uuid4()
        stub.history.update(t, peer_id, 0.9)
        stub.history.update(t, self_id, 0.6)
        score = ReputationProcess._pure_reputation(
            stub, SimpleNamespace(uuid=peer_id))
        # counterparty_score = 0.6, cp_rep = 0.5 → 0.3.
        assert score == pytest.approx(0.3, abs=0.001)


class TestProposerHistoryBilateral:
    """Bug 4 regression: the proposer's local history must record a
    bilateral transaction after both peers paxos-commit for the same
    task_id.  Before the fix, `forward_transaction` wrote
    (task_id, self, self_score) immediately and `handle_accepted` for
    the proposer's own round wrote the same tuple again, filling p2
    with self.  Subsequent peer submissions were then dropped by
    `TransactionHistory.update` (len(tx)==2 guard).

    These tests simulate the post-commit step (handle_accepted's call
    to `self.history.update`) directly, bypassing the paxos messaging
    that's already exercised by the conformance scenarios.  The
    invariant we pin is purely about *what ends up in history*."""

    def test_proposer_history_records_bilateral(self):
        self_id, peer_id = uuid4(), uuid4()
        history = TransactionHistory()
        task = uuid4()

        # Proposer's own paxos commit (was preceded by the now-removed
        # local forward_transaction write).
        history.update(task, self_id, 0.9)
        # Peer's paxos commit for the same task arrives.
        history.update(task, peer_id, 0.3)

        tx = history[task]
        # Both slots filled and the two peers are distinct.
        assert {tx.p1_id, tx.p2_id} == {self_id, peer_id}
        # Score for self is 0.9, for peer is 0.3.
        if tx.p1_id == self_id:
            assert tx.p1_score == pytest.approx(0.9)
            assert tx.p2_score == pytest.approx(0.3)
        else:
            assert tx.p2_score == pytest.approx(0.9)
            assert tx.p1_score == pytest.approx(0.3)

    def test_committed_broadcast_writes_acceptor_history(self):
        """Phase 3 (Bug 5 fix): a peer receiving a `committed`
        broadcast must write (task_id, proposer_id, score) to its
        own history — *unless* the broadcast is its own bounce-back,
        in which case handle_accepted already wrote it locally."""
        from autonomous_trust.core.reputation.protocol import (
            ReputationProtocol,
        )
        from autonomous_trust.core.config import to_json_string

        self_id, peer_id = uuid4(), uuid4()
        history = TransactionHistory()

        stub = SimpleNamespace()
        stub.history = history
        stub.identity = SimpleNamespace(uuid=self_id)
        stub.logger = SimpleNamespace(
            warning=lambda *a, **k: None, debug=lambda *a, **k: None,
            info=lambda *a, **k: None)

        task = uuid4()
        msg = SimpleNamespace(
            function=ReputationProtocol.committed,
            obj=to_json_string((task, peer_id, 0.7)),
        )
        ReputationProcess.handle_committed(stub, {}, msg)

        # Acceptor wrote the proposer's entry.
        tx = history[task]
        assert tx.p1_id == peer_id
        assert tx.p1_score == pytest.approx(0.7)
        assert tx.p2_id is None  # only the proposer's slot is filled

        # Bouncing-back broadcast from self — should be skipped to
        # avoid double-write (handle_accepted already wrote it).
        msg_self = SimpleNamespace(
            function=ReputationProtocol.committed,
            obj=to_json_string((task, self_id, 0.9)),
        )
        ReputationProcess.handle_committed(stub, {}, msg_self)
        # Re-fetch; p2 must still be empty.
        tx = history[task]
        assert tx.p2_id is None

    def test_bilateral_via_two_commits(self):
        """Putting the two halves together: a proposer's own
        handle_accepted writes their entry; the peer's committed
        broadcast then fills the second slot.  This is the path
        CTFT relies on for non-default scoring."""
        from autonomous_trust.core.reputation.protocol import (
            ReputationProtocol,
        )
        from autonomous_trust.core.config import to_json_string

        self_id, peer_id = uuid4(), uuid4()
        history = TransactionHistory()
        task = uuid4()

        # 1. Self's handle_accepted reaches majority — writes
        #    (task, self, 0.9) directly.  We simulate that with a
        #    plain history.update.
        history.update(task, self_id, 0.9)
        assert {history[task].p1_id, history[task].p2_id} == {self_id, None}

        # 2. Peer's committed broadcast arrives.  Our handle_committed
        #    fills the second slot.
        stub = SimpleNamespace(
            history=history,
            identity=SimpleNamespace(uuid=self_id),
            logger=SimpleNamespace(
                warning=lambda *a, **k: None, debug=lambda *a, **k: None,
                info=lambda *a, **k: None),
        )
        msg = SimpleNamespace(
            function=ReputationProtocol.committed,
            obj=to_json_string((task, peer_id, 0.3)),
        )
        ReputationProcess.handle_committed(stub, {}, msg)

        tx = history[task]
        assert {tx.p1_id, tx.p2_id} == {self_id, peer_id}

    def test_forward_transaction_does_not_write_history(self):
        """Direct guard against Bug 4 regressing: forward_transaction
        must NOT touch history.  We stub _start_paxos so we don't
        have to build a real paxos environment — the assertion is
        purely that forward_transaction leaves history empty."""
        self_id = uuid4()
        history = TransactionHistory()
        start_paxos_calls = []

        stub = SimpleNamespace()
        stub.history = history
        stub.identity = SimpleNamespace(uuid=self_id)
        stub.logger = SimpleNamespace(
            error=lambda *a, **k: None, debug=lambda *a, **k: None)
        stub._start_paxos = lambda q, m: start_paxos_calls.append((q, m))

        task = uuid4()
        ts = TransactionScore(task_id=task, score=0.9)

        ReputationProcess.forward_transaction(stub, queues={}, message=ts)

        # _start_paxos was called…
        assert len(start_paxos_calls) == 1
        assert start_paxos_calls[0][1] is ts
        # …but history is still empty.
        assert len(history) == 0
