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
"""A DRAT refutation checker: the UNSAT half of the ``sat`` certificate.

R+D.md §12.3. A peer claiming a formula is satisfiable can prove it in one
line --- hand over the assignment. A peer claiming it is *un*satisfiable cannot
exhibit anything so simple, and "I searched and found nothing" is precisely the
claim a lying peer makes for free. DRAT is what makes that claim checkable: the
peer emits the sequence of lemmas its solver derived, and the checker replays
them, confirming each is implied by what came before, ending at the empty
clause.

The check is the standard one (Heule, Hunt and Wetzler, "Trimming while
checking clausal proofs", FMCAD 2013). A lemma is accepted when it is:

* **RUP** (reverse unit propagation) --- assume every literal of the lemma is
  false, propagate units over the current formula, and reach a conflict. This
  says the lemma is logically implied, and it covers the overwhelming majority
  of lemmas real solvers emit; or
* **RAT** on its first literal --- every resolvent of the lemma against a
  clause containing the negated pivot is itself RUP. This is the weaker
  condition that admits the clause-*addition* steps (blocked clauses, extended
  resolution) that implication alone would reject.

Deletions are applied as they appear. They are not optional bookkeeping: a
proof's cost is dominated by propagation over the live clause set, and a
checker that ignored deletions would do asymptotically more work than the
solver did.

Written with counters rather than watched literals. Watched literals are how a
solver does this fast, but they carry occurrence lists that have to be
maintained identically on both sides of a two-runtime port, and this checker is
verifying a bounded proof from a peer rather than running a search. The cap
that keeps it bounded is ``max_proof_len`` in the declaration; correctness here
is worth more than constant factors, and an unbounded proof is refused rather
than chased.

The C twin is ``src/c/autonomous_trust/certificates/drat.c``.
"""

from __future__ import annotations

from typing import Iterable, Optional, Sequence

#: Ceiling on the clause set the checker will hold, independent of the
#: declaration's proof-length cap. A proof that grows the formula past this is
#: refused rather than allowed to exhaust the process -- the input is a
#: peer-supplied blob, and unbounded work on peer input is a denial of service
#: with extra steps.
MAX_CLAUSES = 200000


class DratError(ValueError):
    """A malformed proof or formula. Distinct from "the proof is wrong"."""


def _normalise_clause(clause: Iterable) -> Optional[list[int]]:
    """Coerce one clause to a de-duplicated list of non-zero ints.

    Returns None if the clause is a tautology (contains both ``l`` and
    ``-l``), which every step below can treat as trivially true.
    """
    seen: set[int] = set()
    out: list[int] = []
    for lit in clause:
        if isinstance(lit, bool) or not isinstance(lit, int):
            raise DratError(f'literal must be a non-zero integer, got {lit!r}')
        if lit == 0:
            # DIMACS terminates a clause with 0; inside a JSON list it is not
            # a literal and quietly dropping it would silently shorten the
            # clause, which changes what the proof proves.
            raise DratError('literal 0 is not valid inside a clause')
        if -lit in seen:
            return None
        if lit not in seen:
            seen.add(lit)
            out.append(lit)
    return out


def _propagate(clauses: Sequence[list[int]], assign: dict[int, bool]) -> bool:
    """Unit-propagate to fixpoint. True if a conflict was reached.

    ``assign`` maps a variable to the value it has been forced to, and is
    extended in place.
    """
    changed = True
    while changed:
        changed = False
        for clause in clauses:
            unassigned = 0
            last = 0
            satisfied = False
            for lit in clause:
                var = lit if lit > 0 else -lit
                val = assign.get(var)
                if val is None:
                    unassigned += 1
                    last = lit
                    if unassigned > 1:
                        # Two free literals: this clause can force nothing and
                        # cannot be in conflict. Stop early -- with counters
                        # this is the whole of the optimisation.
                        break
                elif val == (lit > 0):
                    satisfied = True
                    break
            if satisfied or unassigned > 1:
                continue
            if unassigned == 0:
                return True                      # every literal false
            assign[last if last > 0 else -last] = last > 0
            changed = True
    return False


def is_rup(clauses: Sequence[list[int]], lemma: Sequence[int]) -> bool:
    """True when ``lemma`` is implied by ``clauses`` via unit propagation."""
    assign: dict[int, bool] = {}
    for lit in lemma:
        var = lit if lit > 0 else -lit
        want = lit < 0                            # falsify the literal
        prev = assign.get(var)
        if prev is not None and prev != want:
            # The lemma asserts a literal and its negation; it is a tautology
            # and holds vacuously. _normalise_clause screens these out, so
            # reaching here means a caller built a resolvent by hand.
            return True
        assign[var] = want
    return _propagate(clauses, assign)


def is_rat(clauses: Sequence[list[int]], lemma: Sequence[int]) -> bool:
    """True when ``lemma`` may be added: RUP, or RAT on its first literal."""
    if is_rup(clauses, lemma):
        return True
    if not lemma:
        # The empty clause has no pivot, so RAT does not apply: the only way to
        # end a refutation is for the empty clause to be genuinely implied.
        return False
    pivot = lemma[0]
    for clause in clauses:
        if -pivot not in clause:
            continue
        resolvent: list[int] = [lit for lit in lemma if lit != pivot]
        seen = set(resolvent)
        tautology = False
        for lit in clause:
            if lit == -pivot:
                continue
            if -lit in seen:
                tautology = True
                break
            if lit not in seen:
                seen.add(lit)
                resolvent.append(lit)
        if tautology:
            continue          # a tautological resolvent is trivially implied
        if not is_rup(clauses, resolvent):
            return False
    return True


def check_refutation(formula: Iterable, proof: Iterable,
                     max_proof_len: int = 100000) -> tuple[bool, str]:
    """Replay ``proof`` against ``formula``. Returns ``(valid, reason)``.

    ``formula`` is a list of clauses (each a list of non-zero ints).
    ``proof`` is a list of steps: a clause to add, or ``{"d": [...]}`` to
    delete one. A valid refutation ends by deriving the empty clause.

    ``valid`` False means the proof does not establish unsatisfiability, which
    is evidence about the peer. A :class:`DratError` means the blob is
    malformed, which is a different finding and is raised rather than returned.
    """
    clauses: list[list[int]] = []
    for clause in formula:
        norm = _normalise_clause(clause)
        if norm is None:
            continue                     # a tautology constrains nothing
        if len(clauses) >= MAX_CLAUSES:
            raise DratError(f'formula exceeds {MAX_CLAUSES} clauses')
        clauses.append(norm)

    steps = 0
    derived_empty = False
    for step in proof:
        steps += 1
        if steps > max_proof_len:
            raise DratError(f'proof exceeds the declared {max_proof_len} steps')
        if isinstance(step, dict):
            target = step.get('d')
            if target is None:
                raise DratError('a proof step object must carry "d"')
            norm = _normalise_clause(target)
            if norm is None:
                continue
            key = sorted(norm)
            for idx, existing in enumerate(clauses):
                if sorted(existing) == key:
                    # Delete ONE match. Deleting every duplicate would remove
                    # clauses the proof still relies on, and a checker that
                    # drops a clause the solver kept can reject a valid proof.
                    del clauses[idx]
                    break
            continue

        norm = _normalise_clause(step)
        if norm is None:
            continue                     # adding a tautology is a no-op
        if not is_rat(clauses, norm):
            return False, ('lemma %r is neither RUP nor RAT against the '
                           'clauses derived before it' % (norm,))
        if len(clauses) >= MAX_CLAUSES:
            raise DratError(f'proof grows the formula past {MAX_CLAUSES} clauses')
        clauses.append(norm)
        if not norm:
            derived_empty = True

    if not derived_empty:
        # The single most important check in the file. A proof of a hundred
        # sound lemmas that never reaches the empty clause has proved nothing
        # about satisfiability, and accepting it would let a peer claim UNSAT
        # by emitting arbitrary valid inferences.
        return False, 'the proof never derives the empty clause'
    return True, ''
