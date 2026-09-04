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
"""The arithmetic of the coverage audit: set membership and the exact test.

Split out from :mod:`.audit` because this is the half that has to be
*identical* in the C twin (``src/c/autonomous_trust/calibration/conformal.c``),
down to the order of operations. Everything here is pure: no state, no clock,
no configuration.

**The test.** A peer emits prediction sets at a claimed coverage ``c`` and we
observe ``k`` hits in ``n`` resolved predictions. Under the null hypothesis
that the peer's true coverage is at least ``c``, the number of hits is
stochastically at least ``Binomial(n, c)``, so

    p = P(X <= k),  X ~ Binomial(n, c)

is a valid p-value against the one-sided alternative "true coverage is below
what was claimed". Reject --- call the peer overconfident --- when
``p < audit_alpha``.

This is exact and finite-sample: no asymptotics, no distributional assumption
beyond independence of the resolutions, which is what makes it the right
instrument for a peer that has only made thirty predictions. It is the
hypothesis-test dual of the Clopper-Pearson interval, chosen over the interval
itself because the tail sum needs nothing but ``lgamma`` --- available and
identical in both runtimes --- where an interval would need an inverse
incomplete beta that C has no library for and that would have to be
reimplemented and kept in step.

**One-sided on purpose.** An over-CAUTIOUS peer, whose sets cover far more
often than advertised, is not penalised here. Its sets are useless and that
shows up as poor competence wherever competence is measured; it is not
dishonest about its own limits, and the whole point of this layer
(doc/verification_oracle.md, "Layer 3") is to separate the two.

**Why log space.** ``(1 - c)^n`` underflows to zero for the coverages that
matter --- ``0.1 ** 512`` is not representable --- and a naive recurrence from
that term returns a tail of exactly 0.0, i.e. "reject", for every peer. The
terms are summed as logs with a max-shift, and the comparison against
``audit_alpha`` is made in log space too, so nothing underflows on either side.
"""

from __future__ import annotations

import math

__all__ = ['binomial_tail_log', 'covers', 'overconfident']


def covers(lo, hi, actual, tolerance: float = 0.0) -> bool:
    """Is ``actual`` inside the prediction set, component-wise?

    The set is a box: a conformal prediction set for a real-valued target is
    an interval, and for a vector target the natural multi-output form is the
    product of per-component intervals. A miss on ANY component is a miss,
    which is the conservative reading and the one that matches "the set
    contains the outcome".

    ``tolerance`` widens each side. It exists because the realized value
    arrives through the same observation path as any other measurement and
    carries the same quantisation; it defaults to zero, i.e. take the peer's
    set at its word.
    """
    if len(lo) != len(hi) or len(lo) != len(actual):
        return False
    for low, high, value in zip(lo, hi, actual):
        if not (low - tolerance) <= value <= (high + tolerance):
            return False
    return True


def binomial_tail_log(k: int, n: int, p: float) -> float:
    """``log P(X <= k)`` for ``X ~ Binomial(n, p)``.

    Returns ``-inf`` for a tail of exactly zero. ``k >= n`` is the whole mass,
    ``log 1 = 0.0``.
    """
    if n <= 0:
        return 0.0          # no trials: the tail is everything
    if k >= n:
        return 0.0
    if k < 0:
        return -math.inf
    # p at the boundaries makes log(p) or log1p(-p) infinite, and the term for
    # i = 0 (or i = n) would then evaluate 0 * -inf = NaN. Both cases have an
    # exact answer, so take it rather than letting a NaN through.
    if p <= 0.0:
        return 0.0          # X is 0 almost surely, and k >= 0
    if p >= 1.0:
        return -math.inf    # X is n almost surely, and k < n

    log_p = math.log(p)
    log_q = math.log1p(-p)

    # log C(n, i) by the recurrence rather than via lgamma, and this is the
    # one thing in the file that is about the C twin rather than about
    # statistics: CPython's `math.lgamma` is its OWN implementation, not a call
    # into libm, so the two runtimes disagree in the last few ulp and the
    # identical-arithmetic claim would be false. `log` and `log1p` DO go
    # straight to libm on both sides, and the recurrence uses nothing else --
    # every argument is an exact small integer. Verified bit-identical against
    # the C implementation over the whole (k, n, p) grid the tests pin.
    terms = []
    log_choose = 0.0                       # log C(n, 0) = 0
    for i in range(k + 1):
        if i > 0:
            log_choose += math.log(n - i + 1) - math.log(i)
        terms.append(log_choose + i * log_p + (n - i) * log_q)

    biggest = max(terms)
    if biggest == -math.inf:
        return -math.inf
    total = 0.0
    for term in terms:
        total += math.exp(term - biggest)
    return biggest + math.log(total)


def overconfident(hits: int, n: int, claimed: float, audit_alpha: float) -> bool:
    """Does the record reject the peer's claimed coverage?

    ``True`` means the shortfall is larger than sampling noise explains at the
    ``audit_alpha`` level. Callers are responsible for not asking before they
    have enough resolutions to matter --- this function will happily reject on
    n = 1 if the arithmetic says so, and the minimum-sample policy belongs with
    the configuration, not here.
    """
    if n <= 0 or audit_alpha <= 0.0:
        return False
    if audit_alpha >= 1.0:
        return True
    return binomial_tail_log(hits, n, claimed) < math.log(audit_alpha)
