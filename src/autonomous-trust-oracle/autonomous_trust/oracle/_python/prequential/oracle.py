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
"""Prequential competence (R+D.md §12.5): an observe arm that keeps the record,
and the competence multiplier the core reads when it builds each score
(``..oracles``). The Python twin of ``prequential_oracle.c``. Until
FEATURE_SPLIT_PLAN Phase 3 this lived in ``automate``.
"""
from __future__ import annotations

import logging
import traceback
from typing import Optional

from autonomous_trust.core import oracles
from .competence import NEUTRAL_COMPETENCE, PrequentialEstimator
from .model import PrequentialDeclarationError

#: Process-wide prequential estimator, built lazily from ``$AT_PREQUENTIAL``. A
#: singleton because the competence multiplier IS the accumulated record of
#: resolved forecasts, so a fresh estimator per result would weight every peer
#: at exactly 1.0 forever.
#:
#: It resolves a reporting capability to the quantity it reports through
#: :func:`..oracles.reported_quantity`, the same link the coverage audit uses.
_PREQUENTIAL: 'PrequentialEstimator | None' = None


def prequential_estimator() -> PrequentialEstimator:
    """The process-wide estimator, built on first call.

    This is also the access point for the aggregation half: an in-process
    application asks ``prequential_estimator().combine(quantity, now)`` for the
    mesh's aggregate forecast, and ``.regret(quantity)`` for the realized
    regret and Hedge's bound on it. Nothing in AT core consumes either.
    """
    global _PREQUENTIAL
    if _PREQUENTIAL is None:
        try:
            _PREQUENTIAL = PrequentialEstimator.from_env(
                physics_model=oracles.ReportedQuantities())
        except PrequentialDeclarationError:
            logging.getLogger(__name__).error(
                'prequential: declaration rejected, layer stays OFF: %s',
                traceback.format_exc())
            _PREQUENTIAL = PrequentialEstimator()
    return _PREQUENTIAL


def _observe(inp: oracles.ScoreInput) -> None:
    """Both halves, as an observe arm. This layer renders NO verdict -- it
    produces the weight multiplier :func:`_competence` returns -- so putting it
    among the verdict arms would make the record depend on which other layer
    happened to speak first: a forecast on a reply whose certificate arm is
    about to score it still has to be recorded. After physics for the same
    reason the audit's settle is: a refuted observation must not resolve an
    honest forecaster's forecast, and a refuted result records no forecast of
    its own either.

    Settle before observe, so a peer forecasting the same quantity it just
    reported is weighted against a record including everything this result
    settled."""
    estimator = prequential_estimator()
    if not estimator.enabled:
        return
    resolved = estimator.settle(inp.cap, inp.task.result, inp.subject, inp.now)
    if resolved and inp.logger is not None:
        inp.logger.debug('%s: task %s resolved %d outstanding forecast(s)',
                         inp.name, inp.task.uuid, resolved)
    estimator.observe(inp.cap, getattr(inp.task, 'prediction', None),
                      inp.subject, inp.now)


def _competence(capability: Optional[str], subject: Optional[str]) -> float:
    """:data:`NEUTRAL_COMPETENCE` -- 1.0, the authored ``transaction_weight``
    verbatim -- whenever the layer is off, the capability is undeclared, or the
    record is too short to say anything."""
    estimator = prequential_estimator()
    if not estimator.enabled:
        return NEUTRAL_COMPETENCE
    return estimator.competence(subject, capability)


def _reset() -> None:
    global _PREQUENTIAL
    _PREQUENTIAL = None


oracles.declare('prequential', _reset)
oracles.register_arm(oracles.Arm('prequential.observe', 210, observe=_observe))
oracles.provide_competence(_competence)
