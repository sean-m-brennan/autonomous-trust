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
"""Adjudicating a replicated task by agreement (R+D.md §12.6, slice B).

Once :mod:`.sampling` has said a task is replicated, several executors return a
result for it and this decides what that says about each. It is deliberately
the same shape as the certificate layer's verifier: :func:`evaluate` returns the
*finding* (a per-executor verdict, so the conformance corpus can pin the finding
itself), and :func:`verify` maps a verdict to the ``(score, channel)`` the
reputation process would fold in --- or to ``None`` when there is nothing to
score.

**What agreement can and cannot settle.** Three outcomes, and the third is the
whole reason slice C exists:

* **corroborated** --- the executor's result agrees with a strict majority (or
  every result agrees). Its work is confirmed by an independent executor, which
  is a *good* score on the ``replication`` channel, already weighted twice for
  being corroborated by construction (R+D.md §12.8).
* **outvoted** --- the executor stands in the minority against a strict
  majority. Its result was contradicted by more executors than held it, which
  is a *bad* score.
* **dispute** --- no strict majority exists (the commonest case, two executors
  disagreeing). Nobody is scored. A majority is not an oracle (the doc is
  explicit), so one replica's say-so must never let it defame the executor it
  was checking; a two-way disagreement is precisely what the bisection game
  (slice C) resolves, by localizing the fault to a single step rather than
  taking a vote.

**Agreement, defined so it is deterministic.** Two numeric results agree when
they differ by at most the capability's declared ``tolerance`` (default exact);
anything else agrees only on exact equality. The majority is the result value
the most executors agree with, taken in input order on a tie, and it must be
held by strictly more than half of them --- ``2 * count > n`` --- or the verdict
is ``dispute``. Input-order tie-breaking and the strict-majority test are what
keep the C twin bit-identical: an agreement relation that is not transitive
(``a ~ b`` and ``b ~ c`` but ``a !~ c`` under a loose tolerance) could otherwise
be resolved two ways.

The C twin is ``src/c/autonomous_trust/replication/adjudication.c``.
"""

from __future__ import annotations

from typing import Any, Optional

from autonomous_trust.core.reputation import TX_CHANNEL_REPLICATION

#: An executor whose result a strict majority shared: its work is corroborated.
CORROBORATED = 'corroborated'
#: An executor in the minority against a strict majority: contradicted.
OUTVOTED = 'outvoted'
#: No strict majority: nobody is scored, and the bisection game takes over.
DISPUTE = 'dispute'
#: Fewer than two results: nothing was replicated, so there is nothing to say.
SINGLE = 'single'

#: A corroborated result, scored on the replication channel. The same number
#: the certificate layer gives a proved-right answer: an independent executor
#: reproducing the work is positive evidence, not merely the absence of a
#: refutation.
CORROBORATED_SCORE = 0.9
#: An outvoted result: contradicted by the majority. The certificate layer's
#: proved-wrong number.
OUTVOTED_SCORE = 0.1


def _agree(a: Any, b: Any, tolerance: float) -> bool:
    """Whether two results count as the same answer.

    Numbers agree within ``tolerance`` (``bool`` excluded: ``True == 1`` would
    make a boolean result agree with a numeric one); everything else agrees only
    on exact equality, which is also what ``tolerance = 0`` means for numbers.
    """
    a_num = isinstance(a, (int, float)) and not isinstance(a, bool)
    b_num = isinstance(b, (int, float)) and not isinstance(b, bool)
    if a_num and b_num:
        return abs(float(a) - float(b)) <= tolerance
    return a == b


def adjudicate(results: list[tuple[str, Any]],
               tolerance: float = 0.0) -> dict[str, str]:
    """Return a per-executor verdict for one replicated task.

    ``results`` is ``[(peer, value), ...]`` in the order the executors are to be
    considered, which fixes the tie-break. Fewer than two results is
    :data:`SINGLE` for whoever is present -- nothing was actually replicated.
    """
    n = len(results)
    if n < 2:
        return {peer: SINGLE for peer, _ in results}

    best_index = -1
    best_count = 0
    for i, (_peer, vi) in enumerate(results):
        count = sum(1 for (_p, vj) in results if _agree(vi, vj, tolerance))
        if count > best_count:
            best_count = count
            best_index = i

    if best_count * 2 > n:
        majority = results[best_index][1]
        return {peer: (CORROBORATED if _agree(v, majority, tolerance)
                       else OUTVOTED)
                for peer, v in results}
    return {peer: DISPUTE for peer, _ in results}


def verify(verdict: str) -> Optional[tuple[float, str]]:
    """Map one executor's verdict to the ``(score, channel)`` the reputation
    process folds in, or ``None`` when the verdict carries no score.

    ``dispute`` and ``single`` return ``None``: a disputed task is handed to the
    bisection game rather than scored, and an un-replicated one was never in
    question. Split from :func:`adjudicate` for the same reason the certificate
    layer splits its two, so the corpus can pin the finding apart from the
    number.
    """
    if verdict == CORROBORATED:
        return CORROBORATED_SCORE, TX_CHANNEL_REPLICATION
    if verdict == OUTVOTED:
        return OUTVOTED_SCORE, TX_CHANNEL_REPLICATION
    return None
