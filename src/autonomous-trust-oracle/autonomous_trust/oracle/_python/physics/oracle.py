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
"""Physical consistency (R+D.md §12.2) as a scorer arm (``..oracles``), and the
provider of the capability -> reported-quantity lookup the coverage audit and
the prequential layer settle through. The Python twin of ``physics_oracle.c``.
Until FEATURE_SPLIT_PLAN Phase 3 this lived in ``automate``.
"""
from __future__ import annotations

import logging
import traceback
from typing import Optional

from autonomous_trust.core import oracles
from autonomous_trust.core.reputation import TX_CHANNEL_PHYSICAL
from .checker import PhysicsChecker
from .model import PhysicsDeclarationError

#: Process-wide physical-consistency checker, built lazily from ``$AT_PHYSICS``
#: on first use. One per process, because it carries the observation window
#: that the multi-peer intersection and the parity residuals are computed over;
#: a fresh checker per result would see no history and could only ever perform
#: the single-claim checks.
_PHYSICS: 'PhysicsChecker | None' = None


def physics_checker() -> PhysicsChecker:
    """The process-wide checker, built on first call.

    A malformed declaration is fatal at load (see ``physics.model``), but it
    must not take down the scoring path on every subsequent result: the
    failure is logged once and the layer stays off, which is the same
    end state as never having configured it.
    """
    global _PHYSICS
    if _PHYSICS is None:
        try:
            _PHYSICS = PhysicsChecker.from_env()
        except PhysicsDeclarationError:
            logging.getLogger(__name__).error(
                'physics: declaration rejected, layer stays OFF: %s',
                traceback.format_exc())
            _PHYSICS = PhysicsChecker()
    return _PHYSICS


def _check(inp: oracles.ScoreInput) -> Optional[tuple[float, str]]:
    """After the known-answer probe and before every other arm: a proof attests
    that a computation was performed, not that its answer is physically
    coherent, so a valid proof over a refuted claim is still a refuted claim.
    It returns None -- the common case -- for anything it has no declaration
    for, and a claim that merely survives the check earns nothing here;
    falsification is the only thing this layer is entitled to say."""
    checker = physics_checker()
    if not checker.enabled:
        return None
    verdict = checker.check(inp.cap, inp.task.result, subject=inp.subject,
                            now=inp.now)
    if verdict is not None and inp.logger is not None:
        score, channel = verdict
        # Name which verdict this was, not just the number: "refuted" and
        # "implicated" warrant different attention from an operator, and the
        # channel is the only thing that distinguishes them downstream.
        inp.logger.warning(
            '%s: task %s %s by physical consistency, scored %.2f on '
            'the %s channel', inp.name, inp.task.uuid,
            'REFUTED' if channel == TX_CHANNEL_PHYSICAL
            else 'implicated', score, channel)
    return verdict


def _quantity(capability: str) -> Optional[str]:
    """The declared quantity a capability REPORTS, or None. The link lives in
    physics.json (each quantity names its reporting capability); providing it
    from here is what lets the calibration and prequential layers stay
    independent of this one."""
    quantity = physics_checker().model.for_capability(capability)
    return None if quantity is None else quantity.name


def _reset() -> None:
    global _PHYSICS
    _PHYSICS = None   # rebuilt (window emptied) from $AT_PHYSICS on next use


oracles.declare('physics', _reset)
oracles.register_arm(oracles.Arm('physics.check', 100, score=_check))
oracles.provide_quantity(_quantity)
