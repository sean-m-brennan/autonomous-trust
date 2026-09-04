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
"""Conformal coverage audit: does a peer's advertised coverage hold up?

Build-order step 3 of doc/verification_oracle.md (R+D.md §12.4). The layer
separates two things a scalar reputation conflates:

* **Competence** --- the prediction sets are tight.
* **Honesty about one's own limits** --- the sets cover as advertised.

A peer that is frequently wrong but properly humble is safe to work with. A
peer that is usually right and systematically overconfident scores well right
up until the first time being wrong matters. Averaged reputation cannot see
that peer coming; this can.

**Falsification only.** Like the physics layer and unlike the certificate
layer, a passing audit earns nothing --- there is no score for "has not yet
been caught over-claiming". The only verdicts are a rejected coverage claim and
a prediction that was declared and not delivered. Certificates remain the one
oracle layer entitled to say something GOOD.

**The gradualism the design asks for is the channel weight, not a softened
number.** doc/verification_oracle.md asks that a physics refutation demote a
peer faster than a drifting calibration score. That is already true: both
verdicts are defection-grade scores, and ``physical`` carries a weight of 3
against ``calibration`` at the baseline 1 (R+D.md §12.8). Reproducing the
gradient a second time, by scoring a rejected claim at 0.3 instead of 0.1,
would double-count it. A rejected coverage claim IS a proven-false statement
the peer made about itself.

**Resolution: two paths, physics-declared by default.** A prediction names a
declared quantity, and the ordinary way it comes true is that some later task
result reports that quantity --- the same observation stream the physics
checker consumes, mapped through ``physics.json``'s ``capability`` field. No
application involvement, nothing new to wire. :meth:`CalibrationAuditor.resolve`
is the override, for a ground truth AT never sees as a task result; a domain
whose truth arrives on a serial port is not thereby unauditable.

**Independence, honestly.** The exact test assumes the resolutions are
independent draws. Successive predictions about one slowly-varying quantity are
not, and a peer whose sets are too narrow will produce runs of misses rather
than scattered ones. The consequence is that the test is ANTI-conservative in
exactly the case it is meant to catch, i.e. it will reject an overconfident
peer sooner than the nominal ``audit_alpha`` promises --- and conservative
about clearing one. The direction is the safe one, but the nominal level is a
guide rather than a guarantee, which is why the default is 0.05 and not
something tighter.
"""

from __future__ import annotations

import logging
from collections import deque
from typing import Any, Mapping, Optional, Sequence

from ..reputation import TX_CHANNEL_CALIBRATION
from .conformal import covers, overconfident
from .model import (EMPTY_MODEL, CalibrationModel, Predictive,
                    load_calibration)

logger = logging.getLogger(__name__)

#: A coverage claim the exact test rejects. Defection-grade, like a physical
#: refutation: the peer stated a property of its own output and the record
#: contradicts it.
OVERCONFIDENT_SCORE = 0.1

#: Declared predictive and produced no usable prediction. The mirror of the
#: certificate layer's "declared to certify and did not" --- a fact about the
#: claim, not about the answer, and not evidence of dishonesty.
ABSENT_SCORE = 0.3

__all__ = ['ABSENT_SCORE', 'OVERCONFIDENT_SCORE', 'CalibrationAuditor',
           'Prediction']


class Prediction:
    """One outstanding prediction set, awaiting its outcome."""

    __slots__ = ('capability', 'quantity', 'subject', 'coverage', 'lo', 'hi',
                 'tolerance', 'made_at', 'deadline')

    def __init__(self, capability: str, quantity: str, subject: str,
                 coverage: float, lo: tuple, hi: tuple, tolerance: float,
                 made_at: float, deadline: float):
        self.capability = capability
        self.quantity = quantity
        self.subject = subject
        self.coverage = coverage
        self.lo = lo
        self.hi = hi
        self.tolerance = tolerance
        self.made_at = made_at
        self.deadline = deadline

    def __repr__(self) -> str:  # pragma: no cover - diagnostics
        return (f'Prediction({self.capability}, {self.quantity}, '
                f'{self.subject}, c={self.coverage}, '
                f'[{self.lo}, {self.hi}])')


def _as_floats(value: Any) -> Optional[tuple[float, ...]]:
    """Coerce a scalar or a sequence of scalars to a tuple of floats."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return (float(value),)
    if isinstance(value, str):
        return None
    if isinstance(value, Sequence):
        out = []
        for item in value:
            if isinstance(item, bool) or not isinstance(item, (int, float)):
                return None
            out.append(float(item))
        return tuple(out) if out else None
    return None


class CalibrationAuditor:
    """Per-node coverage audit over the peers this node has heard predict.

    Process-local and unsynchronised, for the same reason the physics store is
    (see :class:`~..physics.checker.PhysicsChecker`): every outcome it counts
    was resolved by this node, and the verdict enters consensus as an ordinary
    ``TransactionScore`` that every peer judges on its own terms.
    """

    def __init__(self, model: Optional[CalibrationModel] = None,
                 physics_model=None, logger_=None):
        self.model = model if model is not None else EMPTY_MODEL
        #: Optional :class:`~..physics.model.PhysicsModel`. Supplies the
        #: capability -> quantity mapping (and the unit) that lets a later
        #: result resolve a prediction with no application involvement.
        self.physics = physics_model
        self.logger = logger_ or logger
        # quantity -> deque[Prediction], oldest first, across all peers: a
        # single observation of the quantity resolves every peer's outstanding
        # prediction about it at once, so the natural key is the quantity.
        self._outstanding: dict[str, deque] = {}
        # subject -> capability -> deque[bool], one entry per resolution.
        self._outcomes: dict[str, dict[str, deque]] = {}

    @classmethod
    def from_env(cls, path=None, physics_model=None,
                 logger_=None) -> 'CalibrationAuditor':
        """Build from ``$AT_CALIBRATION`` (or ``path``). Empty when unset."""
        return cls(load_calibration(path), physics_model=physics_model,
                   logger_=logger_)

    @property
    def enabled(self) -> bool:
        return not self.model.empty

    def reset(self) -> None:
        """Drop all predictions and outcomes. Tests and scenario replays only."""
        self._outstanding.clear()
        self._outcomes.clear()

    # -- the two halves -----------------------------------------------------
    #
    # Split because the caller has to interleave them with the other oracle
    # layers differently. `settle` CONSUMES a result as evidence about the
    # world; `assess` JUDGES a result as a claim about the peer. A scorer runs
    # the first as soon as the result is known not to be refuted, and the
    # second in its place in the arm order. `audit` composes them for callers
    # with no such ordering concern (tests, the conformance adapter).

    def settle(self, capability: Optional[str], result: Any,
               subject: Optional[str] = None,
               now: Optional[float] = None) -> int:
        """Let this result resolve outstanding predictions. Returns how many.

        ``subject`` is the peer that reported it; a peer's own report never
        settles its own prediction (see :meth:`_settle`). ``None`` for either
        argument, or an unattributable result, settles nothing: an observation
        nobody is accountable for is not evidence about anybody.
        """
        if self.model.empty or subject is None or now is None:
            return 0
        return self._resolve_from_result(capability, result, subject, now)

    def assess(self, capability: Optional[str], prediction: Any = None,
               subject: Optional[str] = None,
               now: Optional[float] = None) -> Optional[tuple[float, str]]:
        """Record an attached prediction and report this peer's standing.

        Returns ``None`` --- no verdict --- for a capability that is not
        declared predictive, and for a declared one whose record is still
        shorter than ``min_samples``.
        """
        if self.model.empty or subject is None or now is None:
            return None
        decl = self.model.for_capability(capability)
        if decl is None:
            return None
        return self._record_and_audit(decl, prediction, subject, now)

    def audit(self, capability: Optional[str], result: Any,
              prediction: Any = None, subject: Optional[str] = None,
              now: Optional[float] = None) -> Optional[tuple[float, str]]:
        """:meth:`settle` then :meth:`assess`, in that order.

        Resolution first, so that a peer predicting the same quantity it just
        reported is judged against a record that includes everything this
        result settled.

        ``now`` is a parameter rather than a clock read so a replay produces
        the verdicts the live path did.
        """
        self.settle(capability, result, subject, now)
        return self.assess(capability, prediction, subject, now)

    # -- explicit resolution ------------------------------------------------
    def resolve(self, quantity: str, value: Any,
                now: Optional[float] = None) -> int:
        """Settle outstanding predictions about ``quantity`` with a known truth.

        The override path: for a ground truth AT never sees as a task result.
        ``value`` is in the quantity's declared unit, exactly as a result
        payload would be. Returns how many predictions this settled.
        """
        if self.model.empty or now is None:
            return 0
        actual = _as_floats(value)
        if actual is None:
            self.logger.warning(
                'calibration: cannot resolve %s from %r; expected a number '
                'or a sequence of numbers', quantity, value)
            return 0
        return self._settle(quantity, actual, now, reporter=None)

    # -- internals ----------------------------------------------------------
    def _resolve_from_result(self, capability: Optional[str], result: Any,
                             subject: str, now: float) -> int:
        """The physics-declared path: does this result report a truth?"""
        if self.physics is None or not capability:
            return 0
        quantity = self.physics.for_capability(capability)
        if quantity is None or not self.model.predicts(quantity.name):
            return 0
        payload = result
        if isinstance(result, Mapping):
            payload = result.get('value', result.get('values'))
        actual = _as_floats(payload)
        if actual is None:
            return 0
        return self._settle(quantity.name, actual, now, reporter=subject)

    def _settle(self, quantity: str, actual: tuple, now: float,
                reporter: Optional[str]) -> int:
        pending = self._outstanding.get(quantity)
        if not pending:
            return 0
        settled = 0
        keep: deque = deque(maxlen=pending.maxlen)
        for pred in pending:
            if now > pred.deadline:
                # Expired unresolved. Dropped rather than counted as a miss:
                # nothing was observed, so there is no evidence either way, and
                # counting silence against a peer would let a quiet sensor
                # convict it.
                self.logger.debug(
                    'calibration: prediction by %s about %s expired unresolved',
                    pred.subject, quantity)
                continue
            if reporter is not None and reporter == pred.subject:
                # A peer's own report cannot resolve its own prediction --- that
                # is the peer supplying the truth it is audited against, and it
                # would make the whole layer self-graded. Left outstanding for
                # some other observer to settle.
                keep.append(pred)
                continue
            hit = covers(pred.lo, pred.hi, actual, pred.tolerance)
            self._record_outcome(pred.subject, pred.capability, hit)
            settled += 1
        if keep:
            self._outstanding[quantity] = keep
        else:
            self._outstanding.pop(quantity, None)
        return settled

    def _record_outcome(self, subject: str, capability: str, hit: bool) -> None:
        by_cap = self._outcomes.setdefault(subject, {})
        ring = by_cap.get(capability)
        if ring is None:
            ring = deque(maxlen=self.model.max_outcomes)
            by_cap[capability] = ring
        ring.append(bool(hit))

    def _record_and_audit(self, decl: Predictive, prediction: Any,
                          subject: str, now: float
                          ) -> Optional[tuple[float, str]]:
        parsed, reason = self._parse(decl, prediction)
        if parsed is None:
            self.logger.warning(
                'calibration: %s declares %s predictive and %s',
                subject, decl.capability, reason)
            return ABSENT_SCORE, TX_CHANNEL_CALIBRATION

        ring = self._outstanding.get(decl.quantity)
        if ring is None:
            ring = deque(maxlen=self.model.max_outstanding)
            self._outstanding[decl.quantity] = ring
        ring.append(Prediction(
            capability=decl.capability, quantity=decl.quantity,
            subject=subject, coverage=parsed[0], lo=parsed[1], hi=parsed[2],
            tolerance=decl.tolerance, made_at=now,
            deadline=now + decl.horizon_sec))

        return self._verdict(decl, subject, parsed[0])

    def _verdict(self, decl: Predictive, subject: str, claimed: float
                 ) -> Optional[tuple[float, str]]:
        ring = self._outcomes.get(subject, {}).get(decl.capability)
        n = len(ring) if ring else 0
        if n < self.model.min_samples:
            # Not enough resolved predictions for the test to mean anything.
            # Silence, not leniency: "no verdict" is the honest report, and
            # finite-sample validity is the whole reason to use this test.
            return None
        hits = sum(1 for hit in ring if hit)
        if not overconfident(hits, n, claimed, self.model.audit_alpha):
            return None
        self.logger.warning(
            'calibration: %s claims %.3f coverage on %s and realized %d/%d; '
            'rejected at alpha=%.3f', subject, claimed, decl.capability,
            hits, n, self.model.audit_alpha)
        return OVERCONFIDENT_SCORE, TX_CHANNEL_CALIBRATION

    def _parse(self, decl: Predictive, prediction: Any):
        """Validate an attached prediction. Returns ``(parsed, reason)``."""
        if prediction is None:
            return None, 'attached no prediction'
        if not isinstance(prediction, Mapping):
            return None, f'attached a {type(prediction).__name__}, not a set'

        quantity = prediction.get('quantity')
        if quantity is not None and quantity != decl.quantity:
            return None, (f'predicted {quantity!r}, but the capability is '
                          f'declared to predict {decl.quantity!r}')

        raw_coverage = prediction.get('coverage')
        try:
            coverage = float(raw_coverage)
        except (TypeError, ValueError):
            return None, f'claimed a coverage of {raw_coverage!r}'
        if not decl.coverage_ok(coverage):
            return None, (f'claimed a coverage of {coverage}, outside the '
                          f'declared [{decl.min_coverage}, '
                          f'{decl.max_coverage}]')

        lo = _as_floats(prediction.get('lo'))
        hi = _as_floats(prediction.get('hi'))
        if lo is None or hi is None:
            return None, 'attached a set without numeric lo/hi bounds'
        if len(lo) != len(hi):
            return None, (f'attached {len(lo)} lower bounds and {len(hi)} '
                          'upper bounds')
        for low, high in zip(lo, hi):
            if low > high:
                return None, f'attached an inverted interval [{low}, {high}]'
        return (coverage, lo, hi), ''
