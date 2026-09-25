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
"""The coverage audit (R+D.md §12.4) as two scorer arms (``..oracles``). The
Python twin of ``calibration_oracle.c``. Until FEATURE_SPLIT_PLAN Phase 3 this
lived in ``automate``.
"""
from __future__ import annotations

import logging
import traceback
from typing import Optional

from autonomous_trust.core import oracles
from .audit import CalibrationAuditor, OVERCONFIDENT_SCORE
from .model import CalibrationDeclarationError

#: Process-wide coverage auditor, built lazily from ``$AT_CALIBRATION``.
#: Emphatically process-wide and not per-result: the verdict IS the accumulated
#: record of resolved predictions, so a fresh auditor per result would have
#: nothing to audit and would be permanently silent.
#:
#: It resolves a reporting capability to the quantity it reports through
#: :func:`..oracles.reported_quantity` (the physics layer provides it), which is
#: how a later result resolves an earlier prediction with no application
#: involvement.
_CALIBRATION: 'CalibrationAuditor | None' = None


def calibration_auditor() -> CalibrationAuditor:
    """The process-wide auditor, built on first call."""
    global _CALIBRATION
    if _CALIBRATION is None:
        try:
            _CALIBRATION = CalibrationAuditor.from_env(
                physics_model=oracles.ReportedQuantities())
        except CalibrationDeclarationError:
            logging.getLogger(__name__).error(
                'calibration: declaration rejected, layer stays OFF: %s',
                traceback.format_exc())
            _CALIBRATION = CalibrationAuditor()
    return _CALIBRATION


def _settle(inp: oracles.ScoreInput) -> None:
    """Half one: let this result RESOLVE predictions other peers made about the
    quantity it reports. After physics (order 100), because a refuted result
    is not evidence about the world -- settling an honest forecaster's
    prediction against a refuted observation would let a lying reporter
    convict it. Everything past physics is usable, including a result whose
    own certificate arm is about to score it: a wrong answer to THIS task is
    still a measurement."""
    auditor = calibration_auditor()
    if not auditor.enabled:
        return
    settled = auditor.settle(inp.cap, inp.task.result, inp.subject, inp.now)
    if settled and inp.logger is not None:
        inp.logger.debug('%s: task %s resolved %d outstanding prediction(s)',
                         inp.name, inp.task.uuid, settled)


def _assess(inp: oracles.ScoreInput) -> Optional[tuple[float, str]]:
    """Half two: judge the peer's CLAIM about how often answers of this kind
    land inside the set it quotes. After the certificate arm (order 300),
    because an exact check of THIS answer outranks a statistical claim about a
    hundred of them. Falsification only: a peer not caught over-claiming earns
    nothing, so a silent audit falls through to the arms below."""
    auditor = calibration_auditor()
    if not auditor.enabled:
        return None
    verdict = auditor.assess(inp.cap, getattr(inp.task, 'prediction', None),
                             inp.subject, inp.now)
    if verdict is not None and inp.logger is not None:
        score, channel = verdict
        inp.logger.warning(
            '%s: task %s scored %.2f on the %s channel -- %s',
            inp.name, inp.task.uuid, score, channel,
            'coverage claim rejected by the audit'
            if score == OVERCONFIDENT_SCORE
            else 'declared predictive and produced no usable set')
    return verdict


def _reset() -> None:
    global _CALIBRATION
    _CALIBRATION = None


oracles.declare('calibration', _reset)
oracles.register_arm(oracles.Arm('calibration.settle', 200, observe=_settle))
oracles.register_arm(oracles.Arm('calibration.assess', 400, score=_assess))
