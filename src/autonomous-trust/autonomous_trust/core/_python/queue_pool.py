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

from queue import Empty
from typing import Optional

from .system import QueueType


class PooledQueue(object):
    #: Cap on how many items :meth:`close` will discard. A slot is released by
    #: the process that reserved it, but the peer that was writing to it may
    #: not have stopped yet, so an unbounded drain can spin as fast as a
    #: producer fills. Anything still arriving after this is the next holder's
    #: problem to ignore, which is the lesser fault: a bounded drain can leak a
    #: few stale items, an unbounded one can hang the roster update.
    max_drain = 4096

    def __init__(self, queue_type: type[QueueType]):
        self.in_use = False
        self.queue = queue_type()

    def close(self):
        """Release the slot, discarding anything left in the queue.

        The drain is the point. Clearing ``in_use`` alone hands the next holder
        of this slot whatever the previous one left behind -- a departed peer's
        video frames or sensor readings, arriving under a new peer's name --
        which is a worse fault than the leak that not releasing at all
        produces. Errors are swallowed: a queue whose manager has gone away
        cannot be drained and must still be marked free.
        """
        for _ in range(self.max_drain):
            try:
                self.queue.get_nowait()
            except Empty:
                break
            except Exception:
                # A manager proxy whose server died raises something else
                # entirely (EOFError, BrokenPipeError, ...). Stop draining;
                # the slot is still safe to reuse only in the sense that
                # nothing can read the old contents either.
                break
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

    def release(self, index: int) -> bool:
        """Free the slot at ``index``, draining whatever is left in it.

        The counterpart to :meth:`reserve`, and the one a caller that published
        an index needs: :meth:`recycle` matches on queue identity, which a
        holder of an index does not have. Returns False for an out-of-range
        index (and for a slot already free, which is not an error -- release
        has to be idempotent, because the roster update that calls it can run
        again on a retry).

        **Release in the process that reserved.** ``in_use`` flags are private
        per process after a fork (see :meth:`reserve`), so freeing a slot here
        does not free it in a sibling process, and freeing a slot a sibling
        reserved would hand the same queue to two peers. Every reservation in
        this codebase is made by the roster owner, which is also what releases.
        """
        if index is None or index < 0 or index >= len(self._pool):
            return False
        pq = self._pool[index]
        was_used = pq.in_use
        pq.close()
        return was_used

    def recycle(self, queue: QueueType):
        """Free the slot holding ``queue``, draining it (see
        :meth:`PooledQueue.close`). Prefer :meth:`release` when the index is
        already in hand -- identity matching cannot work across a fork for a
        manager proxy, since each process holds its own proxy object."""
        for pq in self._pool:
            if pq.queue is queue:
                pq.close()
                return True
        return False

    def free_count(self) -> int:
        """How many slots are unreserved in THIS process's view. For
        diagnostics -- an exhaustion message that says how many of the pool
        are actually outstanding is the difference between "sized too small"
        and "slots are leaking"."""
        return sum(1 for pq in self._pool if not pq.in_use)
