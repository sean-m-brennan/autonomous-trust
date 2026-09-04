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
"""The pre-statistical falsification layer itself (R+D.md §12.2).

:class:`PhysicsChecker` takes a returned task result, the capability that was
asked for and the peer that answered, and produces at most one verdict:

* ``(0.1, 'physical')`` --- **refuted**. The claim is impossible, or the peer
  is in every consistent explanation of why the reports cannot all be true.
* ``(0.3, 'swarm_disagreement')`` --- **implicated**. The reports are mutually
  inconsistent and the physics does not say whose fault that is.
* ``None`` --- nothing to say. Not a declared quantity, no answer at all, or
  the claim survived every check.

The third is the common case and the important one. **Passing physics earns a
peer nothing**: a claim outside the feasible set is refuted, but a claim inside
it is merely not-refuted, and rewarding it would turn a falsification layer
into a plausibility grade. So the checker never returns a good score, and the
existing arms of ``score_task_result`` handle the result on their own terms
when it survives.

Ordering, and why this runs where it does. The requestor-side scorer tries the
known-answer probe first, then this, then the certificate arms. A probe knows
the exact right answer, which strictly subsumes asking whether the answer is
possible. Physics comes before the certificate arms because a proof attests
that a computation was performed, not that its output is physically coherent:
a valid proof over a refuted claim is still a refuted claim. Everything below
this layer is statistics, which is what doc/verification_oracle.md means by
running the claim against physics first.

Two design points that are easy to get wrong, and are load-bearing:

**A refuted observation is not stored.** The store feeds the multi-peer
intersection and the parity residuals, so admitting a claim already known to
be impossible would let one liar manufacture conflicts against honest peers.

**An implicated peer is not accused.** Two peers reporting incompatible values
means one of them is wrong; scoring both as refuted would let any peer refute
an honest one by lying about the same quantity. The implicated verdict lands
on ``swarm_disagreement``, which sits at the baseline channel weight precisely
because a majority is not an oracle (R+D.md §12.8).
"""

from __future__ import annotations

import json
import logging
import math
from collections import deque
from typing import Any, Optional, Sequence

from ..reputation import (TX_CHANNEL_PHYSICAL, TX_CHANNEL_SWARM_DISAGREEMENT)
from .diagnose import CLEARED, IMPLICATED, REFUTED, diagnose
from .model import EMPTY_MODEL, PhysicsModel, Quantity, load_physics
from .units import UnitError, parse_unit

logger = logging.getLogger(__name__)

#: Score for a hard falsification. The same number a tampered probe answer
#: gets (automate.score_task_result), and for the same reason: it is the
#: strongest negative evidence AT produces, and the `physical` channel already
#: multiplies its weight by three, so the score itself stays on the ordinary
#: [0,1] scale rather than reaching for a special value.
REFUTED_SCORE = 0.1

#: Score for a peer implicated by a conflict that does not name it uniquely.
#: A poor score, not a refutation -- see the module docstring.
IMPLICATED_SCORE = 0.3


class _Observation:
    """One peer's claim about one quantity, in SI, with its arrival time."""

    __slots__ = ('t', 'values')

    def __init__(self, t: float, values: tuple[float, ...]):
        self.t = t
        self.values = values


class PhysicsCheckError(ValueError):
    """A claim that refutes itself. Carries the reason for the log."""

    def __init__(self, reason: str, detail: str = ''):
        super().__init__(detail or reason)
        self.reason = reason
        self.detail = detail


def _as_floats(value: Any) -> Optional[tuple[float, ...]]:
    """Coerce a claim's value to a tuple of finite floats, or None."""
    if isinstance(value, bool):
        # A bool is an int in Python and would silently read as 0/1. It is not
        # a physical quantity; say so rather than grading it.
        return None
    if isinstance(value, (int, float)):
        v = float(value)
        return (v,) if math.isfinite(v) else None
    if isinstance(value, (list, tuple)):
        out: list[float] = []
        for item in value:
            if isinstance(item, bool) or not isinstance(item, (int, float)):
                return None
            f = float(item)
            if not math.isfinite(f):
                return None
            out.append(f)
        return tuple(out) if out else None
    return None


def _norm(a: Sequence[float], b: Sequence[float]) -> float:
    return math.sqrt(sum((x - y) ** 2 for x, y in zip(a, b)))


class PhysicsChecker:
    """Stateful physical-consistency checker for one node's requestor side.

    The observation store is process-local and unsynchronised, which is
    correct rather than a limitation: the checker runs inside the single
    process that holds the requestor's record of what it asked (Python's main
    process, C's negotiation process), and every value it compares was
    observed by this node. Nothing here is consensus --- the verdict enters
    consensus as an ordinary ``TransactionScore`` and is judged by every peer
    on its own terms.
    """

    def __init__(self, model: Optional[PhysicsModel] = None,
                 logger_=None):
        self.model = model if model is not None else EMPTY_MODEL
        self.logger = logger_ or logger
        # quantity name -> peer key -> deque of _Observation, newest last.
        self._store: dict[str, dict[str, deque]] = {}

    @classmethod
    def from_env(cls, path=None, logger_=None) -> 'PhysicsChecker':
        """Build from ``$AT_PHYSICS`` (or ``path``). Empty when unset."""
        return cls(load_physics(path), logger_=logger_)

    @property
    def enabled(self) -> bool:
        return not self.model.empty

    def reset(self) -> None:
        """Drop every stored observation. Tests and scenario replays only."""
        self._store.clear()

    # -- the entry point ----------------------------------------------------
    def check(self, capability: Optional[str], result: Any,
              subject: Optional[str] = None,
              now: Optional[float] = None) -> Optional[tuple[float, str]]:
        """Judge one returned result. See the module docstring for the contract.

        ``subject`` identifies the peer that answered; ``None`` means the
        result is not attributable to one peer (a fan-out), in which case only
        the checks that need no identity run --- shape, unit, arity and bounds
        --- and nothing is stored. A conflict between peers cannot be assigned
        without knowing who said what, and inventing an identity to file it
        under would be worse than not checking.

        ``now`` is the observation time in seconds. It is a parameter rather
        than a clock read so that a replay -- the conformance corpus, a
        scenario -- produces the same verdicts as the live path did.
        """
        if self.model.empty or result is None:
            # No declarations, or no answer at all. An absent answer is not a
            # false claim; the completion arms of the caller handle it.
            return None
        quantity, payload = self._resolve(capability, result)
        if quantity is None:
            return None

        try:
            values, dim = self._observation(quantity, payload)
        except PhysicsCheckError as exc:
            return self._refute(quantity, subject, exc.reason, exc.detail)

        si = tuple(dim.to_si(v) for v in values)

        try:
            self._check_bounds(quantity, si)
            if subject is not None:
                self._check_kinematics(quantity, subject, si, now)
        except PhysicsCheckError as exc:
            # Deliberately NOT stored: see the module docstring.
            return self._refute(quantity, subject, exc.reason, exc.detail)

        if subject is None:
            return None

        self._record(quantity, subject, si, now)

        conflicts: list[tuple[str, ...]] = []
        conflicts.extend(self._intersection_conflicts(quantity, subject, now))
        conflicts.extend(self._relation_conflicts(quantity, now))
        if not conflicts:
            return None

        verdict = diagnose(conflicts, subject)
        if verdict == REFUTED:
            return self._refute(quantity, subject, 'conflict',
                                'in every minimal diagnosis of %s'
                                % (conflicts,))
        if verdict == IMPLICATED:
            self.logger.info(
                'physics: %s implicated (not refuted) by %s on %s',
                subject, conflicts, quantity.name)
            return IMPLICATED_SCORE, TX_CHANNEL_SWARM_DISAGREEMENT
        assert verdict == CLEARED
        return None

    # -- resolution ---------------------------------------------------------
    def _resolve(self, capability, result):
        """Find the declared quantity and the value payload for a result.

        A result may name its own quantity (``{"quantity": ...}``), which is
        what lets one capability be reused across scenarios; otherwise the
        capability's declaration decides. An unknown name falls back to the
        capability rather than refuting: a peer does not get to pull itself
        out of a check by mislabelling its answer.
        """
        payload = result
        if isinstance(result, str):
            text = result.strip()
            try:
                payload = json.loads(text)
            except (ValueError, TypeError):
                payload = text
        quantity = None
        if isinstance(payload, dict):
            named = payload.get('quantity')
            if isinstance(named, str):
                quantity = self.model.quantities.get(named)
        if quantity is None:
            quantity = self.model.for_capability(capability)
        return quantity, payload

    def _observation(self, quantity: Quantity, payload: Any):
        """Values and their unit, or raise :class:`PhysicsCheckError`."""
        unit_text = None
        value = payload
        if isinstance(payload, dict):
            value = payload.get('value')
            raw_unit = payload.get('unit')
            if raw_unit is not None:
                if not isinstance(raw_unit, str):
                    raise PhysicsCheckError(
                        'unit', 'unit must be a string, got %r' % (raw_unit,))
                unit_text = raw_unit
        elif isinstance(payload, str):
            try:
                value = float(payload)
            except ValueError:
                raise PhysicsCheckError(
                    'not-a-quantity',
                    '%s expects a number, got %r' % (quantity.name, payload)
                ) from None

        values = _as_floats(value)
        if values is None:
            raise PhysicsCheckError(
                'not-a-quantity',
                '%s expects a finite number or vector, got %r'
                % (quantity.name, value))
        if len(values) != quantity.components:
            raise PhysicsCheckError(
                'arity', '%s is declared with %d component(s), got %d'
                % (quantity.name, quantity.components, len(values)))

        dim = quantity.dimension
        if unit_text is not None:
            try:
                claimed = parse_unit(unit_text)
            except UnitError as exc:
                raise PhysicsCheckError('unit', str(exc)) from None
            if not claimed.same_dimension(quantity.dimension):
                raise PhysicsCheckError(
                    'dimension',
                    '%s is declared in %r (%s) but the claim is in %r (%s)'
                    % (quantity.name, quantity.unit, quantity.dimension,
                       unit_text, claimed))
            dim = claimed
        return values, dim

    # -- the checks ---------------------------------------------------------
    def _check_bounds(self, quantity: Quantity, si: Sequence[float]) -> None:
        """Range feasibility, componentwise.

        Componentwise rather than on the magnitude because a declared range is
        a bounding box --- a position north of the pole is refuted whatever
        its distance from the origin. The rate checks below use the magnitude
        instead, because a speed limit is on the vector, not on its axes.
        """
        lo, hi = quantity.si_minimum, quantity.si_maximum
        for i, v in enumerate(si):
            if lo is not None and v < lo:
                raise PhysicsCheckError(
                    'bounds', '%s[%d] = %g is below the declared minimum %g '
                              '(SI)' % (quantity.name, i, v, lo))
            if hi is not None and v > hi:
                raise PhysicsCheckError(
                    'bounds', '%s[%d] = %g exceeds the declared maximum %g '
                              '(SI)' % (quantity.name, i, v, hi))

    def _check_kinematics(self, quantity: Quantity, subject: str,
                          si: Sequence[float], now: Optional[float]) -> None:
        """Feasibility of the CHANGE since this peer's own last claim.

        This is the kinematic half of the layer: not "is the value possible"
        but "could it have got there from where this peer last said it was".
        A peer contradicting its own previous claim is a conflict of size one,
        so it is refuted outright rather than merely implicated.
        """
        if now is None:
            return
        history = self._store.get(quantity.name, {}).get(subject)
        if not history:
            return
        max_rate = quantity.si_max_rate
        max_accel = quantity.si_max_accel
        if max_rate is None and max_accel is None:
            return
        prev = history[-1]
        dt = now - prev.t
        if dt <= 0:
            # Out-of-order or same-instant claims say nothing about a rate.
            # Not a refutation: clock skew and queue reordering are ordinary.
            return
        rate = _norm(si, prev.values) / dt
        if max_rate is not None and rate > max_rate:
            raise PhysicsCheckError(
                'rate', '%s changed at %g/s since this peer\'s own last claim, '
                        'above the declared %g/s (SI)'
                        % (quantity.name, rate, max_rate))
        if max_accel is not None and len(history) >= 2:
            prev2 = history[-2]
            dt_prev = prev.t - prev2.t
            if dt_prev > 0:
                # Vector acceleration: the change in the velocity VECTOR, not
                # in its magnitude, so a reversal is not read as no change.
                v_now = tuple((a - b) / dt for a, b in zip(si, prev.values))
                v_prev = tuple((a - b) / dt_prev
                               for a, b in zip(prev.values, prev2.values))
                span = 0.5 * (dt + dt_prev)
                accel = _norm(v_now, v_prev) / span
                if accel > max_accel:
                    raise PhysicsCheckError(
                        'accel', '%s accelerated at %g/s^2, above the declared '
                                 '%g/s^2 (SI)'
                                 % (quantity.name, accel, max_accel))

    def _intersection_conflicts(self, quantity: Quantity, subject: str,
                                now: Optional[float]):
        """Set-membership intersection over peers reporting one quantity.

        Where errors are bounded rather than stochastic, the intersection of
        the interval constraints is a guaranteed feasible set and a claim
        outside it is refuted rather than improbable (Milanese; Jaulin). Each
        peer's claim becomes ``[v - tolerance, v + tolerance]``; two peers
        whose intervals are disjoint on any component cannot both be right, so
        they form a conflict of size two. Whether either is at fault is the
        diagnosis's problem, not this method's.

        Pairs suffice: on the line, a family of intervals has a common point
        exactly when every pair of them does (Helly in one dimension), so
        enumerating pairs finds every conflict without enumerating subsets.

        Opt-in: with ``tolerance`` unset (zero) the check is skipped entirely.
        A zero-width interval makes every distinct float a conflict, which
        would report disagreement between two honest sensors of the same
        thing.
        """
        tol = quantity.si_tolerance
        if tol <= 0.0 or now is None:
            return []
        peers = self._store.get(quantity.name) or {}
        mine = peers.get(subject)
        if not mine:
            return []
        latest = mine[-1]
        window = self.model.window_sec
        conflicts = []
        for peer, history in peers.items():
            if peer == subject or not history:
                continue
            other = history[-1]
            if abs(now - other.t) > window:
                # Stale. Peers legitimately disagree about a quantity that has
                # moved on since; calling that a conflict refutes honest peers.
                continue
            for a, b in zip(latest.values, other.values):
                if abs(a - b) > 2.0 * tol:
                    conflicts.append((subject, peer))
                    break
        return conflicts

    def _relation_conflicts(self, quantity: Quantity, now: Optional[float]):
        """Parity relations: residuals that vanish under consistency.

        For every declared relation the new observation participates in, and
        where every term has a fresh value, form ``constant + sum(coeff * v)``.
        Under consistency it is zero; a magnitude above the relation's
        tolerance means the contributing reports cannot all be true, and the
        conflict is the set of peers that contributed them --- which is a
        conflict of size one, hence a refutation, when one peer supplied every
        term.

        The freshest value per quantity is used regardless of which peer
        supplied it, because a conservation law constrains the quantities, not
        the reporters.
        """
        if now is None:
            return []
        conflicts = []
        for relation in self.model.relations_for(quantity.name):
            window = (relation.window_sec if relation.window_sec is not None
                      else self.model.window_sec)
            residual = relation.constant
            contributors: list[str] = []
            complete = True
            for qname, coeff in relation.terms:
                best_peer, best = None, None
                for peer, history in (self._store.get(qname) or {}).items():
                    if not history:
                        continue
                    obs = history[-1]
                    if now - obs.t > window:
                        continue
                    if best is None or obs.t > best.t:
                        best_peer, best = peer, obs
                if best is None:
                    complete = False
                    break
                residual += coeff * best.values[0]
                if best_peer not in contributors:
                    contributors.append(best_peer)
            if not complete or not contributors:
                continue
            if abs(residual) > relation.tolerance:
                self.logger.info(
                    'physics: relation %s residual %g exceeds tolerance %g '
                    '(contributors %s)', relation.name, residual,
                    relation.tolerance, contributors)
                conflicts.append(tuple(contributors))
        return conflicts

    # -- store --------------------------------------------------------------
    def _record(self, quantity: Quantity, subject: str,
                si: Sequence[float], now: Optional[float]) -> None:
        if now is None:
            return
        by_peer = self._store.setdefault(quantity.name, {})
        history = by_peer.get(subject)
        if history is None:
            history = deque(maxlen=self.model.max_observations)
            by_peer[subject] = history
        history.append(_Observation(now, tuple(si)))

    def _refute(self, quantity: Quantity, subject: Optional[str],
                reason: str, detail: str) -> tuple[float, str]:
        self.logger.warning(
            'physics: REFUTED %s claim from %s (%s): %s', quantity.name,
            subject or 'an unattributed result', reason, detail)
        return REFUTED_SCORE, TX_CHANNEL_PHYSICAL
