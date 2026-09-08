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
"""Prequential competence: score the record, weight the evidence.

Build-order step 4 of doc/verification_oracle.md (R+D.md §12.5). Dawid's
prequential principle (1984): a forecaster is assessed only by its record of
predictions against outcomes, and never by anything about its internals.

**This layer returns no score.** Every other oracle layer produces
``(score, channel)`` and lands in the reputation algebra as a
``TransactionScore``. This one produces a per-(peer, capability) COMPETENCE
MULTIPLIER on the EMA weight and adds no evidence of its own, because poor
competence is not a defection: a peer whose forecasts are wide or wrong has
told no lie, and scoring it like a physically impossible claim would undo the
distinction R+D.md §12.4 was built to draw. The multiplier is the direct
generalization §12.5 asks for --- the authored per-capability
``transaction_weight``, learned rather than declared --- bounded to a band
around the authored number so the operator's value stays the anchor.

**Sleeping experts.** A peer is scored only on the rounds it actually spoke
(Freund, Schapire, Singer and Warmuth, 1997), which is what makes the
competence REGIONAL --- trusted on thermal, distrusted on attitude --- with
nobody declaring the regions in advance. The same restriction drives the
Hedge weights behind :meth:`PrequentialEstimator.combine`, whose aggregate
forecast is what makes the regret bound a claim about something an application
consumes rather than a property of a table.

See doc/architecture/prequential-competence.md for the design, and the C twin
at ``src/c/autonomous_trust/prequential/``.
"""

from __future__ import annotations

import logging
from typing import Any, Mapping, Optional, Sequence

from .model import EMPTY_MODEL, PrequentialModel, load_prequential
from .scoring import (MAX_LOSS, band_multiplier, hedge_bound, hedge_weights,
                      interval_score, normalized_loss)

logger = logging.getLogger(__name__)

#: The multiplier for anything this layer has nothing to say about: an
#: undeclared capability, a peer with too short a record, or the layer off.
#: Exactly 1.0, i.e. the authored ``transaction_weight`` verbatim.
NEUTRAL_COMPETENCE = 1.0

__all__ = ['Forecast', 'LossRing', 'NEUTRAL_COMPETENCE',
           'PrequentialEstimator']


class LossRing:
    """A bounded ring of resolved losses, in SLOT order.

    Mirrors the C twin's fixed array plus head index rather than wrapping a
    :class:`collections.deque`, and that is not an implementation detail:
    :meth:`mean` is a floating-point sum, so the ORDER the entries are summed
    in is part of the answer, and the two runtimes have to agree to the last
    bit or the same peer gets different weights depending on who scored it.
    """

    __slots__ = ('cap', 'head', 'count', 'losses')

    def __init__(self, cap: int):
        self.cap = max(1, int(cap))
        self.head = 0
        self.count = 0
        self.losses = [0.0] * self.cap

    def append(self, loss: float) -> None:
        self.losses[self.head] = float(loss)
        self.head = (self.head + 1) % self.cap
        if self.count < self.cap:
            self.count += 1

    def mean(self) -> float:
        if self.count <= 0:
            return 0.0
        total = 0.0
        for i in range(self.count):
            total += self.losses[i]
        return total / float(self.count)

    def __len__(self) -> int:
        return self.count


class Forecast:
    """One outstanding forecast, awaiting its outcome."""

    __slots__ = ('capability', 'quantity', 'subject', 'lo', 'hi', 'alpha',
                 'scale', 'tolerance', 'made_at', 'deadline')

    def __init__(self, capability: str, quantity: str, subject: str,
                 lo: tuple, hi: tuple, alpha: float, scale: float,
                 tolerance: float, made_at: float, deadline: float):
        self.capability = capability
        self.quantity = quantity
        self.subject = subject
        self.lo = lo
        self.hi = hi
        self.alpha = alpha
        self.scale = scale
        self.tolerance = tolerance
        self.made_at = made_at
        self.deadline = deadline

    def __repr__(self) -> str:  # pragma: no cover - diagnostics
        return (f'Forecast({self.capability}, {self.quantity}, '
                f'{self.subject}, [{self.lo}, {self.hi}])')


class _PeerRecord:
    """Per-(quantity, peer) Hedge state.

    ``mixture_on_awake`` is the accumulated MIXTURE loss over the rounds this
    peer was awake, which is what makes the sleeping-experts regret
    measurable: the guarantee is against each specialist on its own rounds,
    so comparing a peer's cumulative loss to the mixture's total over ALL
    rounds would be comparing two different sequences.
    """

    __slots__ = ('cumulative_loss', 'rounds', 'mixture_on_awake')

    def __init__(self):
        self.cumulative_loss = 0.0
        self.rounds = 0
        self.mixture_on_awake = 0.0


class _QuantityRecord:
    """Per-quantity Hedge accumulators.

    ``mixture_loss`` is the quantity Hedge actually bounds --- the loss of
    following one peer drawn according to the weights --- and it needs no
    convexity assumption of any kind.

    ``aggregate_loss`` is the loss of the VINCENTIZED forecast, i.e. what an
    application consuming :meth:`PrequentialEstimator.combine` would have
    suffered. On the RAW interval score, which is convex in the endpoints,
    Jensen puts it at or below the mixture. On the NORMALIZED loss it can
    exceed the mixture, because ``min(1, .)`` is not convex: once several
    peers saturate, averaging their endpoints can land the combined interval
    somewhere that scores worse than the capped average of their scores. That
    is not a defect to hide --- it is the honest reading of a bounded loss ---
    so ``saturated_rounds`` counts the rounds where any awake forecast hit the
    ceiling, and the corpus pins the inequality on unsaturated rounds and the
    inversion on saturated ones.
    """

    __slots__ = ('peers', 'rounds', 'mixture_loss', 'aggregate_loss',
                 'saturated_rounds')

    def __init__(self):
        self.peers: dict[str, _PeerRecord] = {}
        self.rounds = 0
        self.mixture_loss = 0.0
        self.aggregate_loss = 0.0
        self.saturated_rounds = 0


def _as_floats(value: Any) -> Optional[tuple]:
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


class PrequentialEstimator:
    """Per-node prequential record over the peers this node has heard forecast.

    Process-local and unsynchronised, for the same reason the physics window
    and the coverage audit's rings are: every loss it holds was resolved by
    this node, and what leaves the node is an ordinary weighted score that
    every peer judges on its own terms.
    """

    def __init__(self, model: Optional[PrequentialModel] = None,
                 physics_model=None, logger_=None):
        self.model = model if model is not None else EMPTY_MODEL
        #: Optional :class:`~..physics.model.PhysicsModel`. Supplies the
        #: reporting-capability -> quantity mapping that lets an ordinary
        #: later result resolve a forecast with no application involvement.
        self.physics = physics_model
        self.logger = logger_ or logger
        # quantity -> list[Forecast], oldest first, across all peers: one
        # observation of the quantity resolves every peer's outstanding
        # forecast about it at once, so the natural key is the quantity.
        self._outstanding: dict[str, list] = {}
        # subject -> capability -> LossRing
        self._losses: dict[str, dict[str, LossRing]] = {}
        # quantity -> _QuantityRecord
        self._hedge: dict[str, _QuantityRecord] = {}

    @classmethod
    def from_env(cls, path=None, physics_model=None,
                 logger_=None) -> 'PrequentialEstimator':
        """Build from ``$AT_PREQUENTIAL`` (or ``path``). Empty when unset."""
        return cls(load_prequential(path), physics_model=physics_model,
                   logger_=logger_)

    @property
    def enabled(self) -> bool:
        return not self.model.empty

    def reset(self) -> None:
        """Drop all forecasts and losses. Tests and scenario replays only."""
        self._outstanding.clear()
        self._losses.clear()
        self._hedge.clear()

    # -- the two halves fed from the scoring path ---------------------------
    #
    # Both sit with the coverage audit's `settle`, immediately after the
    # physics arm: after physics because a refuted observation must not
    # resolve an honest forecaster's forecast, and before every early return
    # because this layer renders no verdict and so has no place in the arm
    # ORDER. A forecast on a reply whose certificate arm is about to score it
    # still has to be recorded, or the record would depend on which other
    # layer happened to speak.

    def settle(self, capability: Optional[str], result: Any,
               subject: Optional[str] = None,
               now: Optional[float] = None) -> int:
        """Let this result resolve outstanding forecasts. Returns how many.

        ``subject`` is the peer that reported it; a peer's own report never
        settles its own forecast, for the reason it never settles its own
        prediction in the coverage audit --- that is the peer supplying the
        truth it is scored against.
        """
        if self.model.empty or subject is None or now is None:
            return 0
        if self.physics is None or not capability:
            return 0
        quantity = self.physics.for_capability(capability)
        if quantity is None or not self.model.forecasts(quantity.name):
            return 0
        payload = result
        if isinstance(result, Mapping):
            payload = result.get('value', result.get('values'))
        actual = _as_floats(payload)
        if actual is None:
            return 0
        return self._settle(quantity.name, actual, now, reporter=subject)

    def observe(self, capability: Optional[str], prediction: Any = None,
                subject: Optional[str] = None,
                now: Optional[float] = None) -> bool:
        """Record an attached forecast. Returns whether it was usable.

        Silent about an unusable one: "declared predictive and attached
        nothing" is a fact about the CLAIM and the coverage audit already
        scores it (0.3 on ``calibration``). Scoring it again here would
        double-count one omission, and this layer has no channel to score it
        on in any case.
        """
        if self.model.empty or subject is None or now is None:
            return False
        decl = self.model.for_capability(capability)
        if decl is None:
            return False
        parsed = self._parse(prediction)
        if parsed is None:
            self.logger.debug(
                'prequential: %s attached no usable forecast for %s',
                subject, decl.capability)
            return False
        lo, hi = parsed
        pending = self._outstanding.setdefault(decl.quantity, [])
        if len(pending) >= self.model.max_outstanding:
            # Full: drop the OLDEST, which is the one closest to expiring
            # unscored anyway.
            del pending[0]
        pending.append(Forecast(
            capability=decl.capability, quantity=decl.quantity,
            subject=subject, lo=lo, hi=hi, alpha=decl.alpha,
            scale=decl.scale, tolerance=decl.tolerance, made_at=now,
            deadline=now + decl.horizon_sec))
        return True

    # -- explicit resolution ------------------------------------------------
    def resolve(self, quantity: str, value: Any,
                now: Optional[float] = None,
                reporter: Optional[str] = None) -> int:
        """Settle outstanding forecasts about ``quantity`` with a known truth.

        The override path, for a ground truth AT never sees as a task result.
        ``value`` is in the quantity's declared unit, exactly as a result
        payload would be. Returns how many forecasts this settled.

        ``reporter`` is the peer that supplied the value, and ``None`` means a
        local observation --- so the default is the local case, which is what
        this path exists for. It is accepted because a caller with a peer
        attributable truth must be able to say so: :meth:`settle` refuses to
        let a peer close its own forecast, and an override path that silently
        could not express the reporter would be a way around that rule rather
        than a convenience. Mirrors the C twin's ``at_prequential_settle``,
        whose ``reporter`` argument means exactly this.
        """
        if self.model.empty or now is None:
            return 0
        actual = _as_floats(value)
        if actual is None:
            self.logger.warning(
                'prequential: cannot resolve %s from %r; expected a number '
                'or a sequence of numbers', quantity, value)
            return 0
        return self._settle(quantity, actual, now, reporter=reporter)

    # -- what the reputation path asks for ----------------------------------
    def competence(self, subject: Optional[str],
                   capability: Optional[str]) -> float:
        """The EMA weight multiplier for this peer on this capability.

        :data:`NEUTRAL_COMPETENCE` --- exactly 1.0, the authored weight
        verbatim --- for an undeclared capability, an unknown peer, or a
        record shorter than ``min_samples``. Silence rather than a guess: the
        weight does not move until there is something to move it with.
        """
        if self.model.empty or subject is None:
            return NEUTRAL_COMPETENCE
        decl = self.model.for_capability(capability)
        if decl is None:
            return NEUTRAL_COMPETENCE
        ring = self._losses.get(subject, {}).get(decl.capability)
        if ring is None or ring.count < self.model.min_samples:
            return NEUTRAL_COMPETENCE
        return band_multiplier(ring.mean(), self.model.band_min,
                               self.model.band_max)

    # -- the aggregation half -----------------------------------------------
    def combine(self, quantity: str,
                now: Optional[float] = None) -> Optional[dict]:
        """The mesh's aggregate forecast for ``quantity``, or ``None``.

        The Hedge-weighted combination of the forecasts currently outstanding
        --- endpoint-wise (vincentized). The interval score is convex in the
        endpoints, so on the raw score Jensen puts this combination's loss at
        or below the weighted average of the peers' losses, which is the
        quantity Hedge bounds against every peer in hindsight. The bounded
        loss the weights are built on saturates, and where it does the
        inequality can invert; :meth:`regret` reports both totals and the
        count of saturated rounds rather than asserting a guarantee the
        normalization does not support.

        Nothing in AT core consumes this. It is the API for an application
        that wants the mesh's best estimate, and it is the claimant for the
        bound (see :meth:`regret`).
        """
        if self.model.empty:
            return None
        awake = [f for f in self._outstanding.get(quantity, [])
                 if now is None or now <= f.deadline]
        if not awake:
            return None
        # One arity, because a box has one shape: take the arity the largest
        # number of forecasts agree on, ties to the earliest, and leave the
        # rest out rather than combining shapes that are not the same claim.
        arities: dict[int, int] = {}
        for f in awake:
            arities[len(f.lo)] = arities.get(len(f.lo), 0) + 1
        best_arity, best_count = 0, 0
        for f in awake:          # slot order, so ties go to the earliest
            n = len(f.lo)
            if arities[n] > best_count:
                best_arity, best_count = n, arities[n]
        awake = [f for f in awake if len(f.lo) == best_arity]
        record = self._hedge.get(quantity)
        weights = hedge_weights(
            [self._cumulative(record, f.subject) for f in awake],
            self.model.eta)
        lo = [0.0] * best_arity
        hi = [0.0] * best_arity
        for weight, f in zip(weights, awake):
            for i in range(best_arity):
                lo[i] += weight * f.lo[i]
                hi[i] += weight * f.hi[i]
        return {
            'quantity': quantity,
            'lo': lo,
            'hi': hi,
            # Every capability forecasting one quantity declares the same
            # alpha and scale (enforced at load), so the aggregate has one
            # unambiguous level -- and the peers' losses are on one scale,
            # which is what makes mixing them meaningful at all.
            'alpha': awake[0].alpha,
            'contributors': [
                {'peer': f.subject, 'capability': f.capability,
                 'weight': weight}
                for weight, f in zip(weights, awake)],
        }

    def regret(self, quantity: str) -> Optional[dict]:
        """Realized regret against every peer, and Hedge's bound on it.

        ``realized`` is the mixture loss accumulated over the rounds that peer
        was awake, minus that peer's own cumulative loss --- the sleeping-
        experts quantity, since the guarantee is against each specialist on
        its OWN rounds. ``bound`` is ``ln N / eta + eta T / 8``. The point of
        returning both is that the guarantee is then measurable rather than
        asserted, and the conformance corpus asserts it against an adversarial
        sequence.
        """
        record = self._hedge.get(quantity)
        if record is None or record.rounds <= 0:
            return None
        n_experts = len(record.peers)
        peers = {}
        for peer, entry in record.peers.items():
            peers[peer] = {
                'cumulative_loss': entry.cumulative_loss,
                'rounds': entry.rounds,
                'realized': entry.mixture_on_awake - entry.cumulative_loss,
                'bound': hedge_bound(n_experts, entry.rounds, self.model.eta),
            }
        return {
            'quantity': quantity,
            'rounds': record.rounds,
            'experts': n_experts,
            # The mixture loss Hedge bounds, and the loss of the aggregate
            # forecast an application would actually have used. The second is
            # at or below the first on the raw interval score (convexity), and
            # may exceed it once losses saturate -- see _QuantityRecord.
            'mixture_loss': record.mixture_loss,
            'aggregate_loss': record.aggregate_loss,
            'saturated_rounds': record.saturated_rounds,
            'peers': peers,
        }

    # -- internals ----------------------------------------------------------
    @staticmethod
    def _cumulative(record: Optional[_QuantityRecord], peer: str) -> float:
        if record is None:
            return 0.0
        entry = record.peers.get(peer)
        return entry.cumulative_loss if entry is not None else 0.0

    def _parse(self, prediction: Any) -> Optional[tuple]:
        """Pull the box out of a §12.4 ``prediction`` payload.

        ``coverage`` is deliberately NOT read: the level this layer scores at
        is the operator's declared ``alpha``, and a peer that could choose it
        would lower it to make its misses cheap (see :mod:`.model`). So a
        prediction carrying no coverage at all is perfectly usable here.
        """
        if not isinstance(prediction, Mapping):
            return None
        lo = _as_floats(prediction.get('lo'))
        hi = _as_floats(prediction.get('hi'))
        if lo is None or hi is None or len(lo) != len(hi):
            return None
        for low, high in zip(lo, hi):
            if low > high:
                return None
        return lo, hi

    def _settle(self, quantity: str, actual: tuple, now: float,
                reporter: Optional[str]) -> int:
        pending = self._outstanding.get(quantity)
        if not pending:
            return 0
        keep = []
        awake = []
        for f in pending:
            if now > f.deadline:
                # Expired unresolved. Dropped rather than scored MAX_LOSS:
                # nothing was observed, so there is no evidence either way,
                # and charging silence to a peer would let a quiet sensor
                # convict an honest forecaster.
                self.logger.debug(
                    'prequential: forecast by %s about %s expired unresolved',
                    f.subject, quantity)
                continue
            if reporter is not None and reporter == f.subject:
                # A peer's own report cannot resolve its own forecast; left
                # outstanding for some other observer to settle.
                keep.append(f)
                continue
            awake.append(f)
        if keep:
            self._outstanding[quantity] = keep
        else:
            self._outstanding.pop(quantity, None)
        if not awake:
            return 0

        losses = []
        for f in awake:
            raw = interval_score(f.lo, f.hi, actual, f.alpha, f.tolerance)
            if raw is None:
                # The forecast committed to a shape the observation
                # contradicts. That is the worst case, not an absent one.
                losses.append(MAX_LOSS)
            else:
                losses.append(normalized_loss(raw, f.scale))

        record = self._hedge.setdefault(quantity, _QuantityRecord())
        weights = hedge_weights(
            [self._cumulative(record, f.subject) for f in awake],
            self.model.eta)
        mixture = 0.0
        for weight, loss in zip(weights, losses):
            mixture += weight * loss

        # The vincentized forecast the aggregate query would have returned,
        # scored the same way, so the Jensen step is checked and not assumed.
        aggregate = self._aggregate_loss(awake, weights, actual)

        record.rounds += 1
        record.mixture_loss += mixture
        record.aggregate_loss += aggregate
        for loss in losses:
            if loss >= MAX_LOSS:
                # A saturated round is the one where the aggregate may score
                # worse than the mixture; counted so that comparison is read
                # with the caveat rather than as a violated guarantee.
                record.saturated_rounds += 1
                break
        for f, loss in zip(awake, losses):
            self._record_loss(f.subject, f.capability, loss)
            entry = record.peers.get(f.subject)
            if entry is None:
                entry = _PeerRecord()
                record.peers[f.subject] = entry
            entry.cumulative_loss += loss
            entry.rounds += 1
            entry.mixture_on_awake += mixture
        return len(awake)

    def _aggregate_loss(self, awake, weights, actual: tuple) -> float:
        """Loss of the weighted-endpoint combination of ``awake``."""
        n = len(actual)
        lo = [0.0] * n
        hi = [0.0] * n
        total = 0.0
        for weight, f in zip(weights, awake):
            if len(f.lo) != n:
                continue
            total += weight
            for i in range(n):
                lo[i] += weight * f.lo[i]
                hi[i] += weight * f.hi[i]
        if not total > 0.0:
            return MAX_LOSS
        # Renormalize over what was included, in case a forecast of another
        # arity was left out -- unconditionally, both because dividing by
        # exactly 1.0 is exact in IEEE and because the C twin's -Wfloat-equal
        # would (rightly) refuse the `total != 1.0` guard that would skip it.
        for i in range(n):
            lo[i] /= total
            hi[i] /= total
        first = awake[0]
        raw = interval_score(tuple(lo), tuple(hi), actual, first.alpha,
                             first.tolerance)
        if raw is None:
            return MAX_LOSS
        return normalized_loss(raw, first.scale)

    def _record_loss(self, subject: str, capability: str,
                     loss: float) -> None:
        by_cap = self._losses.setdefault(subject, {})
        ring = by_cap.get(capability)
        if ring is None:
            ring = LossRing(self.model.max_outcomes)
            by_cap[capability] = ring
        ring.append(loss)
