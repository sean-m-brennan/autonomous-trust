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
"""The arithmetic of selective assignment: weights in, a subset and its exact
inclusion probabilities out (RD_12.7 plan §3.2).

Pure, like :mod:`autonomous_trust.oracle.replication.sampling`, because it is
the half the C twin (``src/c/extensions/selection/draw.c``) must reproduce down
to the operation order: a peer one runtime selects and the other passes over
would make a peer's history depend on which implementation was asking.

**Exact by construction.** Exact inclusion probabilities for softmax sampling
without replacement are expensive, so neither draw needs them:

* k = 1 is one categorical draw from ``p_i = floor + (1 - n*floor) * w_i/W``.
  The propensity of the chosen peer is ``p_i`` itself.
* k > 1 is an independent Bernoulli draw per peer with ``pi_i = clamp(k*p_i,
  floor, 1)``. An empty draw falls back to one categorical draw from ``p``,
  so each peer's inclusion probability is ``pi_i + E * p_i``, where ``E`` is
  the probability that the Bernoulli round came up empty. That is the
  propensity logged.

When ``n * floor > 1`` no floor can hold for every peer, so the draw is
uniform, and the result says it was degraded.

**Sums run left to right in canonical order.** Python's ``sum`` of floats is
compensated (3.12+), and C's loop is not, so every sum and product here is an
explicit loop. The eligible peers arrive sorted by uuid string, the same order
in both runtimes.
"""

from __future__ import annotations

from dataclasses import dataclass

from autonomous_trust.oracle.certificates.rng import SplitMix64

_INV_TWO53 = 1.0 / (1 << 53)


def unit(rng: SplitMix64) -> float:
    """One draw in ``[0, 1)``: the high 53 bits of the next output, as
    replication's ``uniform_unit`` takes them."""
    return (rng.next_u64() >> 11) * _INV_TWO53


def seed_of(link: bytes) -> int:
    """The 64-bit SplitMix64 seed a chain link stands for: its first eight
    bytes, big-endian."""
    return int.from_bytes(bytes(link[:8]), 'big')


def propensities(weights, floor: float) -> tuple[list[float], bool]:
    """``(p, degraded)``: the categorical distribution over ``weights``
    with every entry at least ``floor``. A non-positive total weight is
    read as all-equal, and an unsatisfiable floor degrades to uniform."""
    n = len(weights)
    if n == 0:
        return [], False
    if n * floor > 1.0:
        return [1.0 / n] * n, True
    total = 0.0
    for w in weights:
        total += float(w)
    spread = 1.0 - n * floor
    if total <= 0.0:
        return [floor + spread / n for _ in weights], False
    return [floor + spread * (float(w) / total) for w in weights], False


def pick(probs, u: float) -> int:
    """The index whose cumulative interval holds ``u``; the last on a
    rounding shortfall."""
    cum = 0.0
    for i, p in enumerate(probs):
        cum += p
        if u < cum:
            return i
    return len(probs) - 1


@dataclass(frozen=True)
class Draw:
    """One decision: which indices were selected, and each eligible peer's
    inclusion probability. ``kind`` is ``categorical``, ``bernoulli`` or
    ``all`` (k at or above the eligible count). ``fallback`` is True when a
    Bernoulli round came up empty and one categorical draw, at stream offset
    n, chose instead."""

    selected: tuple[int, ...]
    inclusion: tuple[float, ...]
    kind: str
    degraded: bool = False
    fallback: bool = False


def categorical(weights, floor: float, rng: SplitMix64) -> Draw:
    """Select exactly one peer."""
    probs, degraded = propensities(weights, floor)
    if not probs:
        return Draw((), (), 'categorical', degraded)
    return Draw((pick(probs, unit(rng)),), tuple(probs), 'categorical', degraded)


def bernoulli(weights, k: int, floor: float, rng: SplitMix64) -> Draw:
    """Select about ``k`` peers: every one, at probability 1, when ``k`` is at
    least the eligible count."""
    n = len(weights)
    if n == 0:
        return Draw((), (), 'bernoulli')
    if k >= n:
        return Draw(tuple(range(n)), (1.0,) * n, 'all')
    probs, degraded = propensities(weights, floor)
    pis = []
    for p in probs:
        pi = k * p
        if pi < floor:
            pi = floor
        if pi > 1.0:
            pi = 1.0
        pis.append(pi)
    selected = [i for i, pi in enumerate(pis) if unit(rng) < pi]
    empty = 1.0
    for pi in pis:
        empty *= (1.0 - pi)
    fallback = not selected
    if fallback:
        selected = [pick(probs, unit(rng))]
    inclusion = tuple(pi + empty * p for pi, p in zip(pis, probs))
    return Draw(tuple(selected), inclusion, 'bernoulli', degraded, fallback)


def draw(weights, k, floor: float, seed: int) -> Draw:
    """The decision for one task: categorical for k = 1, Bernoulli above."""
    rng = SplitMix64(seed)
    if k is None:
        n = len(weights)
        return Draw(tuple(range(n)), (1.0,) * n, 'all')
    if k == 1:
        return categorical(weights, floor, rng)
    return bernoulli(weights, k, floor, rng)
