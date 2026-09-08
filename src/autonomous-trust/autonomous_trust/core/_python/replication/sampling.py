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
"""The arithmetic of replication sampling: one draw, one decision (R+D.md §12.6).

Build-order step 6 of doc/verification_oracle.md. Replication is correct for
work that resists certification, but replicating *everything* is the expense
that makes people reach for it last. Sampling is the first of the three things
that make it affordable: duplicate a random fraction ``p`` of tasks rather than
all of them. If detection costs a peer a multiplicative reputation loss ``L``
and a completed task gains it ``g``, cheating is unprofitable whenever
``p * L > g``; in AT terms ``L`` is a tier demotion or exclusion, which is
large, so ``p`` can be small (the BOINC volunteer-computing argument, which
transfers directly).

Split out from the rest of the layer, and kept pure, for the same reason
:mod:`autonomous_trust.core.prequential.scoring` is: this is the half that has
to be *identical* in the C twin (``src/c/autonomous_trust/replication/
sampling.c``), down to the operation order. No state, no clock, no
configuration.

**The draw must be unpredictable to the peer, and reproducible for the
corpus.** Both hold when the *seed* is a parameter, exactly as it is for the
Freivalds challenge in the certificate layer (R+D.md §12.3): production draws
it from the verifier's own entropy at check time -- the executor never sees it
until the decision is already made, so it cannot cheat only on the tasks it
knows will go unchecked -- and a replay supplies a fixed one. Deriving the seed
from the task would hand the executor the decision; the seed is the verifier's
record, never anything read back off the work.

**One draw, from the top 53 bits.** ``uniform_unit`` takes a single
:class:`~autonomous_trust.core.certificates.rng.SplitMix64` output and keeps
its high 53 bits as a double in ``[0, 1)`` -- the canonical construction, and
the high bits because SplitMix64's low bits are the weakest. The C twin does
the same shift and the same multiply by ``2**-53`` in the same order, so the
two runtimes decide identically for a given (probability, seed): a task one
replicates and the other skips would let a peer's exposure depend on which
implementation happened to be watching.
"""

from __future__ import annotations

from autonomous_trust.core.certificates.rng import SplitMix64

#: 2**53. The draw keeps 53 bits because that is the mantissa of an IEEE-754
#: double: one more bit and the multiply below would not be exact.
_TWO53 = 1 << 53

#: 2**-53, written once so the Python and C multiplies are the same constant.
_INV_TWO53 = 1.0 / _TWO53


def uniform_unit(seed: int) -> float:
    """A single draw in ``[0.0, 1.0)`` from ``SplitMix64(seed)``.

    The high 53 bits of one 64-bit output, scaled by ``2**-53``. High bits
    because SplitMix64's low bits carry the least entropy; 53 because that is
    exactly the double mantissa, so ``(u >> 11) * 2**-53`` is exact.
    """
    u = SplitMix64(int(seed)).next_u64()
    return (u >> 11) * _INV_TWO53


def clamp_prob(prob: float) -> float:
    """A probability, forced into ``[0.0, 1.0]``.

    A declaration is validated on load, but a per-task override can still arrive
    out of range; clamping (rather than raising) keeps one bad number from
    dropping a whole round, and 0 or 1 is a defensible reading of "never" or
    "always".
    """
    p = float(prob)
    if p < 0.0:
        return 0.0
    if p > 1.0:
        return 1.0
    return p


def should_replicate(prob: float, seed: int) -> tuple[bool, float]:
    """Decide whether to replicate one completed task.

    Returns ``(replicate, draw)``: the boolean the caller acts on, and the draw
    it came from, so a scenario can pin the draw itself and not only the
    decision it fell on either side of. ``draw < p`` (not ``<=``) so ``p = 0``
    replicates nothing even on a zero draw, and ``p = 1`` replicates everything
    since ``draw`` is strictly below 1.
    """
    p = clamp_prob(prob)
    draw = uniform_unit(seed)
    return (draw < p), draw
