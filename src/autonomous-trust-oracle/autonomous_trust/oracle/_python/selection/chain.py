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
"""The requestor's committed seed chain: auditable draws (RD_12.7 plan §0.1).

A draw seeded from anything the requestor picks per task can be ground. A
requestor that seeds from the task uuid can mint uuids until the coin falls
its way. The seed comes from a hash chain instead, committed before the draws
it binds. The requestor draws a secret ``root`` and publishes ``head =
H^N(root)``. Draw n (1-based) is seeded by ``link(n) = H^(N-n)(root)``. Anyone
holding the head checks a link with ``H^n(link) == head``, and a peer that has
already checked an earlier one checks forward from it. Skipping an
unfavorable draw means skipping an index, and the gap is evidence. Moving to a
new chain early re-rolls once per rotation. The new head is accepted only
alongside the old chain's root, which closes the old chain (§0.2), and the log
records every rotation.

``H`` is SHA-256 (libsodium ``crypto_hash_sha256`` in C). ``N`` is 65,536, so
rotation is rare. The requestor keeps a checkpoint every 256 links, so no
link costs more than 256 hashes to produce.
"""

from __future__ import annotations

import hashlib
import os
from typing import Optional

#: Links per chain.
LENGTH = 1 << 16

#: Checkpoint spacing: the most hashes one link costs the requestor.
CHECKPOINT = 256

#: Bytes per link.
LINK_BYTES = 32


def _h(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hash_forward(link: bytes, times: int) -> bytes:
    """``H^times(link)``."""
    for _ in range(times):
        link = _h(link)
    return link


class SeedChain:
    """The requestor's side: a root, its head, and links by index."""

    __slots__ = ('root', 'head', '_checkpoints')

    def __init__(self, root: bytes):
        if len(root) != LINK_BYTES:
            raise ValueError('a chain root is %d bytes' % LINK_BYTES)
        self.root = bytes(root)
        # _checkpoints[j] = H^(j*CHECKPOINT)(root), j = 0 .. LENGTH/CHECKPOINT
        points = [self.root]
        for _ in range(LENGTH // CHECKPOINT):
            points.append(hash_forward(points[-1], CHECKPOINT))
        self._checkpoints = points
        self.head = points[-1]

    @classmethod
    def fresh(cls) -> 'SeedChain':
        """A new chain from the operating system's entropy."""
        return cls(os.urandom(LINK_BYTES))

    def link(self, index: int) -> bytes:
        """The seed for draw ``index`` (1 .. LENGTH); ``link(LENGTH)`` is the
        root itself, the last link a chain gives."""
        if not 1 <= index <= LENGTH:
            raise IndexError('draw index %d out of [1, %d]' % (index, LENGTH))
        depth = LENGTH - index          # hashes above the root
        j, rest = divmod(depth, CHECKPOINT)
        return hash_forward(self._checkpoints[j], rest)


def verify_link(head: bytes, index: int, link: bytes,
                known: Optional[tuple[int, bytes]] = None) -> bool:
    """True when ``link`` is draw ``index`` of the chain committed to by
    ``head``. ``known`` is ``(index, link)`` already checked for that head;
    a later index is checked forward from it, which costs only the gap."""
    if not 1 <= index <= LENGTH or len(link) != LINK_BYTES:
        return False
    if known is not None and known[0] < index:
        return hash_forward(link, index - known[0]) == known[1]
    return hash_forward(link, index) == head


def verify_rotation(old_head: bytes, old_root: bytes) -> bool:
    """True when ``old_root`` closes the chain committed to by ``old_head``."""
    return len(old_root) == LINK_BYTES and hash_forward(old_root, LENGTH) == old_head
