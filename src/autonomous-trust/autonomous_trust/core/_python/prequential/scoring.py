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
"""The arithmetic of prequential competence: the loss, the band, the weights.

Split out from :mod:`.competence` because this is the half that has to be
*identical* in the C twin (``src/c/autonomous_trust/prequential/scoring.c``),
down to the order of operations. Everything here is pure: no state, no clock,
no configuration.

**The loss.** The Winkler interval score (Winkler 1972; Gneiting and Raftery
2007 §6.2), which is a proper scoring rule for a central prediction interval
at level ``1 - alpha``::

    IS = (u - l) + (2/alpha) * max(0, l - y) + (2/alpha) * max(0, y - u)

It decomposes exactly the way this layer needs: the first term is SHARPNESS
and the other two are the MISS PENALTY, so a peer cannot score well by being
vague (wide interval) or by being overconfident (narrow interval that misses).
The degenerate "cover everything" interval that the coverage audit (R+D.md
§12.4) is required to forgive is penalised here, and that division of labour
is the whole reason this layer exists.

``alpha`` is the OPERATOR's level, from the declaration, never the coverage the
peer claimed. A peer that picked its own would lower it to make misses cheap,
and competence at two different levels is not a comparison. See
:mod:`.model`.

**Bounded on purpose.** ``normalized_loss`` divides by the declared scale and
saturates at 1.0. A forecast that misses by ten scales is not usefully worse
than one that misses by five --- "impossible" is the physics layer's verdict to
render --- and the regret bound below REQUIRES losses in [0, 1].

**Cross-runtime identity.** Three things here are about the C twin rather than
about statistics:

* the operation order of the interval score is fixed, and both runtimes write
  it the same way;
* the ring mean sums in SLOT order (see :class:`~.competence.LossRing`), so
  the floating-point summation order is part of the answer;
* ``weight_round`` is ``floor(x + 0.5)`` rather than either language's native
  rounding, because Python's ``round`` is banker's and C's ``lround`` is
  half-away-from-zero, and they disagree at exactly 0.5 --- which is precisely
  where a band-mapped multiplier lands most often.

Unlike the coverage audit's binomial tail, nothing here needs ``lgamma``: the
only transcendentals are ``exp`` and ``log``, and both go straight to libm on
both sides.
"""

from __future__ import annotations

import math

__all__ = ['MAX_LOSS', 'band_multiplier', 'hedge_bound', 'hedge_weights',
           'interval_score', 'normalized_loss', 'weight_round']

#: The loss ceiling. Also what an unresolvable component count scores, so a
#: forecast whose arity does not match the observation is the worst case
#: rather than an absent one -- it committed to a shape the world contradicted.
MAX_LOSS = 1.0


def interval_score(lo, hi, actual, alpha: float,
                   tolerance: float = 0.0) -> float:
    """The Winkler interval score of the box ``[lo, hi]`` against ``actual``.

    The mean over components, so a 3-vector forecast is not three times worse
    than a scalar one. Returns ``None`` when the shapes do not line up; the
    caller decides what that means (:data:`MAX_LOSS`, in this layer).

    ``tolerance`` forgives a MISS within measurement error, and deliberately
    does not enlarge the sharpness term: it models what is unknown about
    ``actual``, which can only bear on whether the value fell outside the
    interval. The width is the peer's own declaration and is known exactly, so
    charging the widened one would bill every peer on a coarsely measured
    quantity for our instrument -- and would put a floor of
    ``2*tolerance/scale`` under a perfect forecaster's loss, making the
    documented "flawless record earns ``band_max``" unreachable on any
    capability that declares a tolerance at all. Same reason the coverage
    audit has a tolerance, applied to the same term.
    """
    n = len(lo)
    if n == 0 or len(hi) != n or len(actual) != n:
        return None
    penalty = 2.0 / alpha
    total = 0.0
    for i in range(n):
        # Sharpness from the DECLARED interval, misses judged against the
        # widened one. See the tolerance paragraph above.
        low = lo[i] - tolerance
        high = hi[i] + tolerance
        y = actual[i]
        term = hi[i] - lo[i]
        if y < low:
            term += penalty * (low - y)
        elif y > high:
            term += penalty * (y - high)
        total += term
    return total / float(n)


def normalized_loss(score: float, scale: float) -> float:
    """``min(1, score / scale)``, the bounded loss the weights are built on.

    A negative interval score is impossible (every term is non-negative for a
    non-inverted interval), but an inverted one would produce it, so the floor
    is applied rather than assumed.
    """
    if not scale > 0.0:
        return MAX_LOSS
    value = score / scale
    if value < 0.0:
        return 0.0
    if value > MAX_LOSS:
        return MAX_LOSS
    return value


def band_multiplier(mean_loss: float, band_min: float,
                    band_max: float) -> float:
    """Map a mean loss in [0, 1] onto the declared weight band.

    ``mean_loss`` 0 (a perfectly sharp forecaster) maps to ``band_max`` and 1
    (saturated) to ``band_min``. Linear, deliberately: a nonlinear map would be
    a tuning surface, and there is nothing to tune it against -- what the
    number has to be is monotone in the record and inside the range the
    operator authorised.
    """
    if mean_loss < 0.0:
        mean_loss = 0.0
    elif mean_loss > MAX_LOSS:
        mean_loss = MAX_LOSS
    return band_max - (band_max - band_min) * mean_loss


def weight_round(value: float) -> int:
    """``floor(value + 0.5)``, clamped to at least 1.

    The EMA applies a weight by folding the score in that many times
    (``consensus_score_from_window``), so the composed weight has to be a
    positive integer. 1 is therefore the floor, which is why a capability
    authored at ``transaction_weight: 1`` cannot be demoted by competence --
    see doc/architecture/prequential-competence.md, which records that as a
    limitation rather than working around it.
    """
    if not math.isfinite(value):
        return 1
    rounded = int(math.floor(value + 0.5))
    return rounded if rounded > 1 else 1


def hedge_weights(cumulative_losses, eta: float) -> list:
    """Normalized exponential weights ``exp(-eta L_i) / sum_j exp(-eta L_j)``.

    Computed in log space with a max-shift, because ``exp(-eta L)`` underflows
    to zero for the cumulative losses a long run produces --- and a table of
    zeros normalizes to a division by zero, i.e. no aggregate at all, for
    exactly the run lengths where the regret bound starts to be worth having.

    The caller passes only the AWAKE peers' cumulative losses (the sleeping-
    experts restriction, Freund, Schapire, Singer and Warmuth 1997), so the
    normalization is over the awake set and a peer that did not forecast this
    round is neither rewarded nor punished for it.
    """
    n = len(cumulative_losses)
    if n == 0:
        return []
    logs = [-eta * float(loss) for loss in cumulative_losses]
    biggest = max(logs)
    shifted = [math.exp(value - biggest) for value in logs]
    total = 0.0
    for value in shifted:
        total += value
    if not total > 0.0:
        # Cannot happen after the max-shift (one term is exp(0) = 1), but a
        # uniform answer is the right fallback and costs nothing.
        return [1.0 / float(n)] * n
    return [value / total for value in shifted]


def hedge_bound(n_experts: int, rounds: int, eta: float) -> float:
    """``ln N / eta + eta * T / 8``: Hedge's regret bound for bounded losses.

    Reported alongside the realized regret so the guarantee is measurable
    rather than asserted. ``N`` is the number of peers that have ever
    forecast the quantity and ``T`` the rounds the peer in question was awake.
    """
    if n_experts < 1 or not eta > 0.0:
        return 0.0
    if rounds < 0:
        rounds = 0
    return math.log(float(n_experts)) / eta + eta * float(rounds) / 8.0
