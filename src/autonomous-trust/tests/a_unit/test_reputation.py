import pytest
from uuid import uuid4

from autonomous_trust.core.reputation.reputation import (
    TransactionScore, Transaction, TransactionHistory,
    Reputation, Reputations,
)


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
