# ******************
#  Copyright 2023 TekFive, Inc., Sean M. Brennan, and contributors
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

from typing import Optional

from .system import QueueType


class PooledQueue(object):
    def __init__(self, queue_type: type[QueueType]):
        self.in_use = False
        self.queue = queue_type()

    def close(self):
        self.in_use = False


class QueuePool(object):
    """Cannot create multiproc queues after pool is started, so create a reserve pool of them"""
    pool_size = 128

    def __init__(self, queue_type: type[QueueType]):
        self._pool: list[PooledQueue] = []
        for _ in range(self.pool_size):
            self._pool.append(PooledQueue(queue_type))

    def next(self) -> Optional[QueueType]:
        for pq in self._pool:
            if not pq.in_use:
                pq.in_use = True
                return pq.queue
        return None

    def reserve(self) -> Optional[int]:
        """Claim a free slot and return its INDEX rather than the queue itself.

        The index is the part that can be shared. The pool is built before any
        worker is forked, so slot *i* is the same underlying queue in every
        process -- whereas each process's ``in_use`` flags are its own private
        copy, so two processes calling :meth:`next` independently agree only by
        accident of ordering. Anything that must hand a queue to another process
        reserves a slot here and publishes the index; the other side resolves it
        with :meth:`slot`.
        """
        for idx, pq in enumerate(self._pool):
            if not pq.in_use:
                pq.in_use = True
                return idx
        return None

    def slot(self, index: int) -> Optional[QueueType]:
        """The queue at ``index``, without claiming it.

        For the receiving side of a published assignment: the sender already
        owns the slot, and marking it in_use here would only consume a second
        one from this process's private view of the pool.
        """
        if index is None or index < 0 or index >= len(self._pool):
            return None
        return self._pool[index].queue

    def recycle(self, queue: QueueType):
        for pq in self._pool:
            if pq.queue is queue:
                pq.close()
