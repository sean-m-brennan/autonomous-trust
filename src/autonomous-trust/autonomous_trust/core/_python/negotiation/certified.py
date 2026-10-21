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
"""Certified-result wire helpers (R+D.md §12.3) the core keeps.

The ``certificate`` field of a reply and the :class:`Certified` wrapper are
negotiation wire format: a worker splits a certifying capability's result
before it goes on the wire whether or not this node can CHECK witnesses, so
these stay in the core while the checking lives in the certificates layer
(FEATURE_SPLIT_PLAN Phase 3). The Python half of ``negotiation/neg_certified.h``.
"""
from __future__ import annotations

import os


class Certified:
    """What a certifying capability returns: an answer and its witness.

    An explicit wrapper rather than a convention on the return value. The
    alternatives all guess: a 2-tuple is indistinguishable from a capability
    that genuinely returns a pair, and a ``{"value": ..., "certificate": ...}``
    dict is indistinguishable from an answer that happens to be a mapping with
    those keys. Guessing here would mean a capability's witness silently
    becoming part of its answer, or the reverse, and the checker would then be
    verifying the wrong object.

    The executor unwraps this into the result and the separate ``certificate``
    field of the reply, so the wire carries the two apart --- which is what
    lets a reader that does not know the checker still read the answer.
    """

    __slots__ = ('value', 'certificate')

    def __init__(self, value, certificate=None):
        self.value = value
        self.certificate = certificate

    def __repr__(self):  # pragma: no cover - diagnostics only
        return f'Certified({self.value!r}, {self.certificate!r})'


def split_certified(result):
    """Return ``(value, certificate)`` for a possibly-wrapped result."""
    if isinstance(result, Certified):
        return result.value, result.certificate
    return result, None


def default_seed() -> int:
    """A fresh 64-bit verifier challenge seed.

    ``os.urandom`` rather than the ``random`` module: the requirement is that
    the peer could not have predicted this before it answered, and a
    process-global PRNG that anything else in the node may have observed or
    reseeded is a weaker claim than it looks.
    """
    return int.from_bytes(os.urandom(8), 'big')
