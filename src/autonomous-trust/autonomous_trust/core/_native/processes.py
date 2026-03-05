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
Native wrappers for C process framework.

Provides:
- NativeTracker: wraps tracker_t for process registration
- NativeQueue: wraps queue_t for IPC messaging
- MessageType: Python enum matching message_type_t
- messaging helpers: send/recv via C unix socket IPC
"""

import enum

from ._ffi import ffi, lib


class MessageType(enum.IntEnum):
    """Message type enumeration matching C ``message_type_t``."""
    SIGNAL = 1
    GROUP = 2
    PEER = 3
    PEER_CAPABILITIES = 4
    TASK = 5
    NET_MESSAGE = 6
    TASK_STATUS = 7
    TASK_RESULT = 8
    TRANSACTION_SCORE = 9


class TaskStatusVal(enum.IntEnum):
    """Task status matching C ``task_status_val_t``."""
    RUNNING = 1
    SLEEPING = 2
    ZOMBIE = 3
    STOPPED = 4
    DEAD = 5
    PENDING = 6
    UNKNOWN = 7


class NativeQueue:
    """Wrapper around C ``queue_t`` — a unix domain socket IPC endpoint."""

    __slots__ = ('_ptr',)

    def __init__(self, queue_id: str | None = None, *, _ptr=None):
        if _ptr is not None:
            self._ptr = _ptr
        else:
            self._ptr = ffi.new('queue_t *')
            if queue_id is not None:
                id_buf = ffi.new('char[]', queue_id.encode('utf-8'))
                rc = lib.messaging_init(id_buf, self._ptr)
                if rc != 0:
                    raise RuntimeError(f"messaging_init failed with rc={rc}")

    @property
    def key(self) -> str:
        return ffi.string(self._ptr.key).decode('utf-8')

    @property
    def fd(self) -> int:
        return self._ptr.fd

    def assign(self):
        """Set this queue as the current process's receive queue."""
        lib.messaging_assign(self._ptr)

    def close(self):
        """Close this queue."""
        lib.messaging_qclose(self._ptr)

    def __repr__(self):
        return f'NativeQueue(key={self.key!r}, fd={self.fd})'


class NativeTracker:
    """Wrapper around C ``tracker_t`` — process registration tracker."""

    __slots__ = ('_ptr', '_owned')

    def __init__(self, logger=None, *, _ptr=None, _owned=True):
        if _ptr is not None:
            self._ptr = _ptr
            self._owned = _owned
        else:
            tracker_ptr = ffi.new('tracker_t **')
            tracker_ptr[0] = ffi.cast('tracker_t *', 0x1)
            logger_ptr = logger if logger is not None else ffi.NULL
            rc = lib.tracker_create(tracker_ptr, logger_ptr)
            if rc != 0:
                raise RuntimeError(f"tracker_create failed with rc={rc}")
            self._ptr = tracker_ptr[0]
            self._owned = True

    def __del__(self):
        if self._owned and hasattr(self, '_ptr') and self._ptr is not None:
            lib.tracker_free(self._ptr)

    def __repr__(self):
        return 'NativeTracker()'


def messaging_send(key: str, msg_type: MessageType, msg_data,
                   blocking: bool = False) -> int:
    """Send a message to a named queue.

    Args:
        key: Destination queue key.
        msg_type: Message type enum value.
        msg_data: Raw CFFI pointer to message data.
        blocking: Whether to block until delivered.

    Returns:
        0 on success, error code otherwise.
    """
    key_buf = ffi.new('char[]', key.encode('utf-8'))
    return lib.messaging_send(key_buf, int(msg_type), msg_data, blocking)


def messaging_close():
    """Close the global messaging system."""
    lib.messaging_close()
