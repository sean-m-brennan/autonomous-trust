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
Native wrappers for C reputation types.

Provides protocol constants and wrappers for tx_history_t / reputations_t,
plus the reputation computation algorithms.
"""

import uuid as _uuid

from .._ffi import ffi, lib

# Re-export everything from the Python reputation module for API compatibility
from ..._python.reputation.reputation import *  # noqa: F401, F403
from ..._python.reputation.repprocess import ReputationProcess  # noqa: F401


class ReputationProtocol:
    """Protocol message constants matching C ``#define`` values."""
    REQUEST = "request permission"
    GRANT = "grant permission"
    NACK = "nack"
    BACKDATE = "backdate"
    TX = "transaction"
    ACCEPTED = "accepted"
    OUTDATED = "outdated"
    UPDATE = "update"
    REP_REQ = "reputation request"
    REP_RESP = "reputation response"


class TransactionHistory:
    """Wrapper around C ``tx_history_t`` — blockchain of transactions."""

    __slots__ = ('_ptr',)

    def __init__(self):
        ptr_holder = ffi.new('tx_history_t **')
        rc = lib.tx_history_create(ptr_holder)
        if rc != 0:
            raise RuntimeError(f"tx_history_create failed with rc={rc}")
        self._ptr = ptr_holder[0]

    def update(self, task_uuid: _uuid.UUID, peer_uuid: _uuid.UUID,
               score: float):
        """Record a transaction score."""
        task_buf = ffi.new('unsigned char[16]', task_uuid.bytes)
        peer_buf = ffi.new('unsigned char[16]', peer_uuid.bytes)
        rc = lib.tx_history_update(self._ptr, task_buf, peer_buf, score)
        if rc != 0:
            raise RuntimeError(f"tx_history_update failed with rc={rc}")

    def __len__(self):
        return lib.tx_history_len(self._ptr)

    def __del__(self):
        if hasattr(self, '_ptr') and self._ptr is not None:
            lib.tx_history_destroy(self._ptr)
            self._ptr = None

    def __repr__(self):
        return f'TransactionHistory(len={len(self)})'


class Reputations:
    """Wrapper around C ``reputations_t`` — peer reputation scores."""

    __slots__ = ('_ptr',)

    def __init__(self):
        ptr_holder = ffi.new('reputations_t **')
        rc = lib.reputations_create(ptr_holder)
        if rc != 0:
            raise RuntimeError(f"reputations_create failed with rc={rc}")
        self._ptr = ptr_holder[0]

    def update(self, peer_uuid: _uuid.UUID, score: float):
        """Update a peer's reputation score."""
        uuid_buf = ffi.new('unsigned char[16]', peer_uuid.bytes)
        rc = lib.reputations_update(self._ptr, uuid_buf, score)
        if rc != 0:
            raise RuntimeError(f"reputations_update failed with rc={rc}")

    def get(self, peer_uuid: _uuid.UUID) -> float:
        """Get a peer's reputation score."""
        uuid_buf = ffi.new('unsigned char[16]', peer_uuid.bytes)
        score_ptr = ffi.new('double *')
        rc = lib.reputations_get(self._ptr, uuid_buf, score_ptr)
        if rc != 0:
            raise RuntimeError(f"reputations_get failed with rc={rc}")
        return score_ptr[0]

    def contains(self, peer_uuid: _uuid.UUID) -> bool:
        """Check if a peer exists in the reputation map."""
        uuid_buf = ffi.new('unsigned char[16]', peer_uuid.bytes)
        return bool(lib.reputations_contains(self._ptr, uuid_buf))

    def __del__(self):
        if hasattr(self, '_ptr') and self._ptr is not None:
            lib.reputations_destroy(self._ptr)
            self._ptr = None

    def __repr__(self):
        return 'Reputations()'


def reputation_compute(history: TransactionHistory, reputations: Reputations,
                       self_uuid: _uuid.UUID,
                       peer_uuid: _uuid.UUID) -> float:
    """Compute reputation score for a peer using the hybrid algorithm.

    Uses pure socially-weighted average if trusted (>0.5),
    contrite tit-for-tat otherwise.
    """
    self_buf = ffi.new('unsigned char[16]', self_uuid.bytes)
    peer_buf = ffi.new('unsigned char[16]', peer_uuid.bytes)
    # 5th arg is task_weights (const map_t *); NULL = unweighted aggregator.
    # Omitting it left the C function reading a garbage pointer and segfaulting
    # on the pure-reputation branch (trusted peer). Mirror the no-weights call.
    return lib.reputation_compute(history._ptr, reputations._ptr,
                                  self_buf, peer_buf, ffi.NULL)
