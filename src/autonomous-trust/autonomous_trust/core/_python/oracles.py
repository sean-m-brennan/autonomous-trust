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
"""The oracle registry: how the verification layers of R+D.md §12 (physics,
calibration, certificates, prequential) reach the scorer without the core
naming them.

The Python half of ``negotiation/neg_oracle.h`` (FEATURE_SPLIT_PLAN Phase 3).
Each layer, when its package is imported (:func:`load` finds and imports
them),

* **declares** itself (:func:`declare`), which is what :func:`check_env` looks
  for and where its reset hangs;
* registers its **arms** (:func:`register_arm`): a *verdict* arm may decide the
  score and channel; an *observe* arm only records;
* may **provide** one of two services other layers or the core read: the
  quantity a capability reports (physics) and the competence multiplier
  (prequential).

``automate.score_task_result`` runs the known-answer probe, then the arms in
ascending :attr:`Arm.order` -- the first verdict arm that decides ends scoring
-- then the ZKP and completion arms. The orders the layers use reproduce the
scorer's fixed sequence, and are the C twin's:

    100 physics check (verdict) · 200 calibration settle (observe) ·
    210 prequential settle + observe (observe) · 300 certificate check
    (verdict) · 400 calibration assess (verdict)

Registering at import is safe because importing a layer turns nothing on: each
still speaks only when its declaration (``$AT_PHYSICS``, ...) names a model.
An empty registry scores exactly as the probe, ZKP and completion arms alone.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Any, Callable, Optional

_logger = logging.getLogger(__name__)

#: The competence multiplier with no prequential layer: the authored weight
#: verbatim.
NEUTRAL_COMPETENCE = 1.0

#: The declarations a node's environment can make, and the layer that must be
#: present to honour each. Names only: the core knows what a layer is called,
#: never what it does. Kept here rather than supplied by the layers, because a
#: layer that is absent cannot declare anything -- and the absent one is
#: exactly the case :func:`check_env` exists for. Same table as the C twin's.
DECLARATIONS: tuple[tuple[str, str], ...] = (
    ('AT_PHYSICS', 'physics'),
    ('AT_CALIBRATION', 'calibration'),
    ('AT_PREQUENTIAL', 'prequential'),
    ('AT_CERTIFICATES', 'certificates'),
)


class OracleMissingError(RuntimeError):
    """The environment declares a layer this node does not have."""


@dataclass(frozen=True)
class ScoreInput:
    """One result being scored: ``score_task_result``'s inputs.

    ``task`` is the returned :class:`TaskResult`; the arms read ``result``,
    ``certificate``, ``prediction`` and ``requested_kwargs`` (OUR record of the
    problem) from it. ``subject`` is the peer's uuid string, ``None`` for a
    fan-out. ``seed`` is this verifier's challenge; ``None`` lets the arm that
    needs one draw it fresh (``negotiation.certified.default_seed``), so a
    result nothing checks costs no ``os.urandom``. ``logger`` and ``name`` are
    the caller's, for the arms' log lines.
    """
    task: Any
    cap: Optional[str]
    subject: Optional[str]
    now: float
    seed: Optional[int] = None
    logger: Any = None
    name: str = ''


@dataclass(frozen=True)
class Arm:
    """One scorer arm. Exactly one of ``score`` / ``observe`` is set.

    ``score(inp)`` returns ``(score, channel)`` to decide, or ``None`` to fall
    through to the next arm. ``observe(inp)`` has side effects only.
    """
    name: str
    order: int
    score: Optional[Callable[[ScoreInput], Optional[tuple[float, str]]]] = None
    observe: Optional[Callable[[ScoreInput], None]] = None


_oracles: dict[str, Optional[Callable[[], None]]] = {}
_arms: list[Arm] = []
_quantity_fn: Optional[Callable[[str], Optional[str]]] = None
_competence_fn: Optional[Callable[[str, Optional[str]], float]] = None


def declare(name: str, reset: Optional[Callable[[], None]] = None) -> bool:
    """Declare a layer. Refuses (False, logged) unnamed and duplicate."""
    if not name or name in _oracles:
        _logger.error('oracles: refusing to declare %s layer %r',
                      'a duplicate' if name else 'an unnamed', name)
        return False
    _oracles[name] = reset
    return True


def present(name: str) -> bool:
    """True iff a layer named ``name`` is declared."""
    return name in _oracles


def register_arm(arm: Arm) -> bool:
    """Add an arm. Refuses (False, logged) unnamed, neither or both hooks, and
    a name already registered. Ties keep registration order."""
    if (not arm.name or (arm.score is None) == (arm.observe is None)
            or any(a.name == arm.name for a in _arms)):
        _logger.error('oracles: refusing arm %r', arm.name)
        return False
    _arms.append(arm)
    _arms.sort(key=lambda a: a.order)   # stable: ties keep registration order
    return True


def arms() -> tuple[Arm, ...]:
    """The registered arms, in scorer order."""
    return tuple(_arms)


def score(inp: ScoreInput) -> Optional[tuple[float, str]]:
    """Run the arms over ``inp``. The first verdict arm that decides wins;
    ``None`` if none did."""
    for arm in _arms:
        if arm.observe is not None:
            arm.observe(inp)
            continue
        verdict = arm.score(inp)
        if verdict is not None:
            return verdict
    return None


def provide_quantity(fn: Callable[[str], Optional[str]]) -> bool:
    """Provide the capability -> reported-quantity lookup. One provider; a
    second is refused (False, logged)."""
    global _quantity_fn
    if fn is None or _quantity_fn is not None:
        _logger.error('oracles: refusing a %s quantity provider',
                      'None' if fn is None else 'second')
        return False
    _quantity_fn = fn
    return True


def reported_quantity(capability: Optional[str]) -> Optional[str]:
    """The declared quantity ``capability`` reports, or ``None`` (no provider,
    or not declared)."""
    if _quantity_fn is None or not capability:
        return None
    return _quantity_fn(capability)


class _Quantity:
    __slots__ = ('name',)

    def __init__(self, name: str):
        self.name = name


class ReportedQuantities:
    """:func:`reported_quantity` in the shape the calibration and prequential
    layers take as ``physics_model``: ``for_capability(cap)`` returns an object
    with the quantity's ``name``, or ``None``. It is how those layers resolve
    against the physics declaration without importing the physics layer."""

    def for_capability(self, capability: Optional[str]) -> Optional[_Quantity]:
        name = reported_quantity(capability)
        return None if name is None else _Quantity(name)


def provide_competence(fn: Callable[[str, Optional[str]], float]) -> bool:
    """Provide the competence multiplier ``fn(capability, subject)``. One
    provider; a second is refused (False, logged)."""
    global _competence_fn
    if fn is None or _competence_fn is not None:
        _logger.error('oracles: refusing a %s competence provider',
                      'None' if fn is None else 'second')
        return False
    _competence_fn = fn
    return True


def competence(capability: Optional[str], subject: Optional[str]) -> float:
    """The multiplier for ``subject`` on ``capability``;
    :data:`NEUTRAL_COMPETENCE` with no provider."""
    if _competence_fn is None:
        return NEUTRAL_COMPETENCE
    return _competence_fn(capability, subject)


def check_env(logger=None) -> None:
    """Refuse a node whose environment declares a layer it lacks.

    ``$AT_PHYSICS``, ``$AT_CALIBRATION``, ``$AT_PREQUENTIAL`` or
    ``$AT_CERTIFICATES`` set and non-empty with that layer absent. Checking
    silently not happening is the one outcome worse than not starting -- a
    node declared to test physics would accept results physics refutes. Logs
    an ERROR per missing layer, then raises :class:`OracleMissingError`.
    """
    log = logger if logger is not None else _logger
    missing = []
    for env, name in DECLARATIONS:
        if os.environ.get(env) and not present(name):
            log.error('$%s is set, but the %s layer is not loaded; refusing '
                      'to start rather than skip the check it declares',
                      env, name)
            missing.append(name)
    if missing:
        raise OracleMissingError(
            'declared but not loaded: ' + ', '.join(missing))


def load() -> None:
    """Import every verification layer this node has.

    The layers are a separate distribution (``autonomous-trust-oracle``) that
    the core names nowhere: :func:`.extensions.all_extensions` finds it, by its
    entry point or its source-tree marker, and importing it registers the
    layers here. Call before :func:`check_env`. Idempotent."""
    from .extensions import all_extensions
    all_extensions()


def reset() -> None:
    """Call every declared layer's reset (tests, conformance)."""
    for fn in _oracles.values():
        if fn is not None:
            fn()
