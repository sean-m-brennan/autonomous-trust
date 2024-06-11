# ******************
#  Copyright 2024 TekFive, Inc. and contributors
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
        self.in_use = True


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

    def recycle(self, queue: QueueType):
        for pq in self._pool:
            if pq.queue is queue:
                pq.close()
