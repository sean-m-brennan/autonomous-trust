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
"""Consistency-based diagnosis over peers (Reiter 1987; de Kleer & Williams 1987).

R+D.md §12.2 takes the GDE formulation and substitutes "peer" for "component":
a **conflict** is a set of peers who cannot all be reporting honestly, and a
**diagnosis** is a minimal hitting set over the conflicts --- a smallest set of
peers whose dishonesty would explain every conflict at once. It needs no
reputation history and no learned model, which is what makes it usable at first
contact.

The distinction this module exists to preserve is between *refuted* and
*implicated*, and it is the reason the layer does not simply penalise everyone
who disagrees:

* A peer in EVERY minimal diagnosis is **necessarily faulty**. No consistent
  story leaves it honest. A claim that violates a bound or contradicts the
  peer's own previous claim is the singleton case of exactly this: the conflict
  is ``{peer}``, so the peer is in every hitting set trivially.
* A peer in SOME minimal diagnosis is **implicated but not refuted**. Two peers
  reporting incompatible values for one quantity is the canonical case: one of
  them is wrong and the physics does not say which. Calling that a refutation
  would let any peer refute an honest one by lying about it.
* A peer in NO minimal diagnosis is untouched.

:func:`diagnose` returns that three-way verdict. What each verdict is worth ---
the score and the evidence channel --- is :mod:`.checker`'s decision, not this
module's, because it is a reputation policy rather than a fact about the
conflicts.

**Subset-minimal diagnoses, not cardinality-minimal ones.** The usual GDE
refinement prefers the smallest diagnosis, which would refute a lone outlier
whenever two other peers corroborate each other: conflicts ``{A,C}`` and
``{B,C}`` have minimal diagnoses ``{C}`` and ``{A,B}``, and taking the smaller
convicts C. That is majority rule wearing physics' clothes, and R+D.md §12.8 is
explicit that a majority is not an oracle --- three colluding peers would then
be able to refute an honest one on the hardest channel AT has. Keeping every
subset-minimal diagnosis leaves C *implicated*, which is the true statement:
someone is lying and the physics does not say who.

**Bitmasks, in both runtimes, on purpose.** Peers are indexed by first
appearance across the conflict list and a set is an integer mask. The C twin
(``src/c/autonomous_trust/physics/physics.c``) does the same over ``uint64_t``,
so the two enumerate the same sets in the same order and cannot disagree about
a diagnosis. :data:`MAX_PEERS` is that word width; beyond it the search
degrades deliberately (see :func:`diagnose`).
"""

from __future__ import annotations

from typing import Iterable, Optional, Sequence

#: Width of the peer-set word. The C twin's masks are uint64_t.
MAX_PEERS = 64

#: Cap on the number of conflicts fed to the exhaustive search. Minimal hitting
#: set is NP-hard in general and the enumeration branches on every conflict;
#: real conflict sets here are a handful, so the cap is a guard against a
#: pathological window rather than a normal limit. See :func:`diagnose` for
#: what happens past it -- it is a narrowing of the verdict, never a widening.
MAX_CONFLICTS = 16

#: Cap on the hitting sets the enumeration will materialise. The conflict cap
#: alone does not bound this: sixteen conflicts of sixteen peers each branch to
#: far more sets than anyone wants resident. The C twin's array is this size and
#: it degrades on overflow, so this is not merely a memory guard -- without it
#: a window large enough to overflow C would give one runtime a full diagnosis
#: and the other the narrowed one, which is the divergence the whole layer is
#: pinned against.
MAX_DIAGNOSES = 256

#: The three verdicts. Deliberately not an enum: the C twin returns the same
#: three as an int, and the conformance vectors spell them as these strings.
REFUTED = 'refuted'          #: in every minimal diagnosis
IMPLICATED = 'implicated'    #: in some but not every minimal diagnosis
CLEARED = 'cleared'          #: in none


def minimal_hitting_sets(conflicts: Sequence[int]) -> Optional[list[int]]:
    """Minimal hitting sets of ``conflicts``, each a bitmask of peer indices.

    A hitting set intersects every conflict; minimal means no proper subset of
    it does. Reiter's HS-tree with the usual pruning, written over masks so the
    C mirror can be a transcription rather than a reimplementation.

    An empty conflict list has exactly one minimal hitting set --- the empty
    set --- which is the "nothing to explain" case and clears everyone.

    Returns ``None`` when the enumeration would exceed :data:`MAX_DIAGNOSES`,
    which is how the C twin signals the same thing; :func:`diagnose` then
    narrows the verdict rather than guessing at one.
    """
    # Drop any conflict that is a superset of another: it is hit whenever the
    # smaller one is, so it cannot constrain the result, and removing it cuts
    # the branching factor. (Reiter's pruning of non-minimal conflicts.)
    # A conflict that is a proper superset of another is hit whenever the
    # smaller one is, so it cannot constrain the answer; dropping it only cuts
    # the branching factor. De-duplication keeps first-appearance order, which
    # is what makes the enumeration below reproducible across runtimes.
    seen: set[int] = set()
    ordered: list[int] = []
    for c in conflicts:
        if c == 0 or c in seen:
            continue
        if any(other != c and other != 0 and (other & c) == other
               for other in conflicts):
            continue
        seen.add(c)
        ordered.append(c)
    conflicts = ordered

    if not conflicts:
        return [0]

    results: list[int] = []
    overflow = False

    def _rec(idx: int, current: int) -> None:
        nonlocal overflow
        if overflow:
            return
        # Skip conflicts already hit by `current`.
        while idx < len(conflicts) and (conflicts[idx] & current):
            idx += 1
        if idx == len(conflicts):
            if len(results) >= MAX_DIAGNOSES:
                overflow = True
                return
            results.append(current)
            return
        remaining = conflicts[idx]
        bit = 0
        while remaining:
            if remaining & 1:
                _rec(idx + 1, current | (1 << bit))
            remaining >>= 1
            bit += 1

    _rec(0, 0)
    if overflow:
        return None

    # Keep only the minimal ones. `results` is small (bounded by the product of
    # conflict sizes under MAX_CONFLICTS), so the quadratic filter is cheap and
    # exact, which matters more here than speed.
    minimal: list[int] = []
    for h in results:
        if any(o != h and (o & h) == o for o in results):
            continue
        if h not in minimal:
            minimal.append(h)
    return minimal


def diagnose(conflicts: Iterable[Sequence[str]], subject: str) -> str:
    """Verdict on ``subject`` given conflicts named by peer identifier.

    ``conflicts`` is an iterable of peer-identifier sequences; each is a set of
    peers who cannot all be honest. Returns :data:`REFUTED`,
    :data:`IMPLICATED` or :data:`CLEARED`.

    Past :data:`MAX_CONFLICTS`, or with more than :data:`MAX_PEERS` distinct
    peers, the exhaustive search is skipped and the verdict falls back to the
    singleton test: a peer is refuted only if it forms a conflict by itself,
    and is otherwise implicated if it appears anywhere. That is strictly the
    narrower answer --- the fallback can turn a REFUTED into an IMPLICATED but
    never the reverse --- so an overloaded window costs evidence rather than
    manufacturing it.
    """
    index: dict[str, int] = {}
    masks: list[int] = []
    overflow = False
    materialised = [tuple(dict.fromkeys(c)) for c in conflicts]
    if not materialised:
        return CLEARED
    for c in materialised:
        mask = 0
        for peer in c:
            if peer not in index:
                if len(index) >= MAX_PEERS:
                    overflow = True
                    continue
                index[peer] = len(index)
            mask |= 1 << index[peer]
        if mask:
            masks.append(mask)

    if subject not in index:
        return CLEARED

    if overflow or len(masks) > MAX_CONFLICTS:
        singleton = any(len(c) == 1 and c[0] == subject for c in materialised)
        if singleton:
            return REFUTED
        return IMPLICATED

    subject_bit = 1 << index[subject]
    diagnoses = minimal_hitting_sets(masks)
    if diagnoses is None:
        # The enumeration overflowed; fall back exactly as the conflict cap
        # does, and for the same reason.
        singleton = any(len(c) == 1 and c[0] == subject for c in materialised)
        return REFUTED if singleton else IMPLICATED
    if not diagnoses or diagnoses == [0]:
        return CLEARED
    in_all = all(d & subject_bit for d in diagnoses)
    in_any = any(d & subject_bit for d in diagnoses)
    if in_all:
        return REFUTED
    if in_any:
        return IMPLICATED
    return CLEARED
