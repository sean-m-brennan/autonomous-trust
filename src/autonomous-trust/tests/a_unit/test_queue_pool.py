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
