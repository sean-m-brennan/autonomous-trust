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
import queue

from autonomous_trust.core.queue_pool import PooledQueue, QueuePool


class TestPooledQueue:
    def test_init(self):
        pq = PooledQueue(queue.Queue)
        assert pq.in_use is False
        assert isinstance(pq.queue, queue.Queue)

    def test_close(self):
        pq = PooledQueue(queue.Queue)
        pq.in_use = True
        pq.close()
        assert pq.in_use is False


class TestQueuePool:
    def test_init(self):
        pool = QueuePool(queue.Queue)
        assert len(pool._pool) == QueuePool.pool_size

    def test_next(self):
        pool = QueuePool(queue.Queue)
        q = pool.next()
        assert q is not None
        assert isinstance(q, queue.Queue)

    def test_next_marks_in_use(self):
        pool = QueuePool(queue.Queue)
        q = pool.next()
        # The returned queue's PooledQueue should be marked in_use
        found = False
        for pq in pool._pool:
            if pq.queue is q:
                assert pq.in_use is True
                found = True
                break
        assert found

    def test_next_exhausted(self):
        pool = QueuePool(queue.Queue)
        for _ in range(QueuePool.pool_size):
            pool.next()
        assert pool.next() is None

    def test_recycle(self):
        pool = QueuePool(queue.Queue)
        q = pool.next()
        pool.recycle(q)
        # recycle calls close() which sets in_use=False, making queue available for reuse
        for pq in pool._pool:
            if pq.queue is q:
                assert pq.in_use is False
                break


class TestSlotAssignment:
    """Handing a pooled queue to ANOTHER process means sharing its slot index,
    not the queue: the pool is built before any fork, so slot *i* is the same
    underlying queue everywhere, while each process's in_use flags are its own
    private copy. See the Cohort docstring in inspector/peer/daq.py.
    """

    def test_reserve_returns_an_index_and_claims_it(self):
        pool = QueuePool(queue.Queue)
        idx = pool.reserve()
        assert idx == 0
        assert pool._pool[idx].in_use is True
        assert pool.reserve() == 1          # the next caller gets the next slot

    def test_slot_resolves_without_claiming(self):
        """The receiving side must NOT claim: the sender already owns the slot,
        and claiming here would burn a second one from this process's view."""
        pool = QueuePool(queue.Queue)
        idx = pool.reserve()
        free_before = sum(1 for pq in pool._pool if not pq.in_use)
        assert pool.slot(idx) is pool._pool[idx].queue
        assert sum(1 for pq in pool._pool if not pq.in_use) == free_before

    def test_reserve_and_slot_agree(self):
        pool = QueuePool(queue.Queue)
        assert pool.slot(pool.reserve()) is not pool.slot(pool.reserve())

    def test_slot_rejects_out_of_range(self):
        pool = QueuePool(queue.Queue)
        assert pool.slot(-1) is None
        assert pool.slot(QueuePool.pool_size) is None
        assert pool.slot(None) is None

    def test_reserve_exhausted_returns_none(self):
        pool = QueuePool(queue.Queue)
        for _ in range(QueuePool.pool_size):
            assert pool.reserve() is not None
        assert pool.reserve() is None       # caller must enlarge the pool, not guess
