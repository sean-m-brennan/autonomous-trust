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
"""SplitMix64, the one PRNG both runtimes draw a verifier challenge from.

Freivalds' check (R+D.md §12.3) multiplies by a random vector, and its
soundness rests on the prover not knowing that vector in advance. Two things
follow, and they pull in opposite directions:

* The vector must be **unpredictable to the peer**. Deriving it from the
  matrices --- a hash of the inputs, say --- destroys the guarantee outright:
  the prover chooses ``C``, so it can grind candidate answers until one passes
  a challenge it can compute itself. The challenge has to come from the
  requestor's own entropy, at check time.
* The check must be **reproducible**, or the conformance corpus cannot pin it
  and the two runtimes cannot be shown to agree.

Both hold if the *seed* is a parameter: production draws it from the
requestor's RNG at check time (unpredictable to the peer, who never sees it
until the check is already over), and a replay supplies a fixed one. It is the
same shape as the observation clock in the physics layer, and the same shape as
the probe challenge in R+D.md §12.7 --- the requestor's own record, never
anything read back off the reply.

SplitMix64 (Steele, Lea and Flood, 2014) is the algorithm because it is eight
lines of integer arithmetic with no state beyond a counter, so the C twin at
``src/c/autonomous_trust/certificates/rng.c`` is a transcription rather than a
reimplementation, and the two emit identical streams for identical seeds. It is
not cryptographic and does not need to be: the requirement is that the peer
cannot predict the draw before it answers, which the secrecy of the seed
supplies.
"""

from __future__ import annotations

_MASK = (1 << 64) - 1


class SplitMix64:
    """Deterministic 64-bit stream from a 64-bit seed."""

    __slots__ = ('_state',)

    def __init__(self, seed: int):
        self._state = int(seed) & _MASK

    def next_u64(self) -> int:
        # The reference SplitMix64. Every operation is masked to 64 bits
        # because Python integers do not wrap and C's uint64_t does; without
        # the masks the two streams diverge on the first carry.
        self._state = (self._state + 0x9E3779B97F4A7C15) & _MASK
        z = self._state
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & _MASK
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & _MASK
        return z ^ (z >> 31)

    def next_pm1(self) -> float:
        """A challenge entry: -1.0 or +1.0, from the stream's low bit.

        Freivalds is usually stated over ``{0,1}`` vectors. ``{-1,+1}`` has the
        same one-sided error bound and is better conditioned in floating point:
        a zero entry silently drops a column from the product, so a wrong
        answer that differs only in dropped columns survives a round it should
        have failed.
        """
        return 1.0 if (self.next_u64() & 1) else -1.0
