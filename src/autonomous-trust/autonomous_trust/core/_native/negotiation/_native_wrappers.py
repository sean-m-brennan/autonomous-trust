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

"""
Native wrappers for C negotiation types.

Provides protocol constants and wrappers for job_queue_t / task_tracker_t.
Task and capability types reference opaque C structs, so these wrappers
operate at the queue/tracker level rather than individual task fields.
"""

from .._ffi import ffi, lib

# Re-export everything from the Python negotiation module for API compatibility
from ..._python.negotiation.negotiation import *  # noqa: F401, F403
from ..._python.negotiation.negprocess import NegotiationProcess  # noqa: F401


# Protocol message constants (matching C #define values)
class NegotiationProtocol:
    START = "spawn task"
    ANNOUNCE = "invitation"
    RESPONSE = "haggle"
    ACCEPT = "ack"
    REFUSE = "nack"
    STATUS_REQ = "status request"
    STATUS_RSP = "status response"
    RESULT = "report results"
    CANCEL = "cancel"


class JobQueue:
    """Wrapper around C ``job_queue_t`` — priority queue of scheduled jobs.

    Since job_queue_t contains embedded task_t (which contains opaque
    capability_t), this is treated as opaque and operations go through
    C functions only.
    """

    __slots__ = ('_ptr',)

    def __init__(self):
        ptr_holder = ffi.new('job_queue_t **')
        rc = lib.job_queue_create(ptr_holder)
        if rc != 0:
            raise RuntimeError(f"job_queue_create failed with rc={rc}")
        self._ptr = ptr_holder[0]

    @property
    def count(self) -> int:
        return lib.job_queue_count(self._ptr)

    def clear(self):
        lib.job_queue_clear(self._ptr)

    def __len__(self):
        return self.count

    def __del__(self):
        if hasattr(self, '_ptr') and self._ptr is not None:
            lib.job_queue_destroy(self._ptr)
            self._ptr = None

    def __repr__(self):
        return f'JobQueue(count={self.count})'


class TaskTracker:
    """Wrapper around C ``task_tracker_t`` — tracks results for a task."""

    __slots__ = ('_ptr',)

    def __init__(self, task_uuid: bytes, expected: int):
        """Create a task tracker.

        Args:
            task_uuid: 16-byte UUID of the task.
            expected: Number of expected results.
        """
        uuid_buf = ffi.new('unsigned char[16]', task_uuid)
        ptr_holder = ffi.new('task_tracker_t **')
        rc = lib.task_tracker_create(ptr_holder, uuid_buf, expected)
        if rc != 0:
            raise RuntimeError(f"task_tracker_create failed with rc={rc}")
        self._ptr = ptr_holder[0]

    @property
    def result_count(self) -> int:
        return lib.task_tracker_result_count(self._ptr)

    def set_result(self, peer_uuid: bytes, data: bytes):
        """Record a result from a peer."""
        uuid_buf = ffi.new('unsigned char[16]', peer_uuid)
        data_buf = ffi.new('uint8_t[]', data)
        rc = lib.task_tracker_set_result(
            self._ptr, uuid_buf, data_buf, len(data))
        if rc != 0:
            raise RuntimeError(f"task_tracker_set_result failed with rc={rc}")

    def __del__(self):
        if hasattr(self, '_ptr') and self._ptr is not None:
            lib.task_tracker_destroy(self._ptr)
            self._ptr = None

    def __repr__(self):
        return f'TaskTracker(results={self.result_count})'
