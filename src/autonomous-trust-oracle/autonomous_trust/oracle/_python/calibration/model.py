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
"""The ``calibration.json`` declaration: which capabilities predict, and how.

The *domain* half of R+D.md §12.4, on the same pattern as ``physics.json`` and
``certificates.json``: :mod:`.conformal` owns the arithmetic and cannot be
overridden by an operator; this file says which capability emits prediction
sets, which declared quantity those sets are about, how long a prediction has
to come true, and how much evidence the audit needs before it will speak.

Set ``AT_CALIBRATION`` to a declaration path to turn the layer on. With nothing
set, :func:`load_calibration` returns an EMPTY model and the auditor returns no
verdict for anything, so the mechanism is inert until a scenario opts in --- the
same opt-in default the other two oracle layers take, and for the same reason:
an audit that guessed at which capabilities were meant to be predictive would
be manufacturing evidence.

Schema (version 1)::

    {
      "version": 1,
      "min_samples": 30,        # resolutions before the audit will speak
      "audit_alpha": 0.05,      # false-accusation rate of the coverage test
      "max_outcomes": 256,      # per (peer, capability); ring bound
      "max_outstanding": 64,    # unresolved predictions per (peer, quantity)
      "horizon_sec": 60.0,      # default deadline for a prediction to resolve
      "capabilities": {
        "sat.thermal-forecast": {
          "quantity": "sat.bus-temp",   # what the sets are ABOUT
          "horizon_sec": 120.0,         # overrides the model default
          "min_coverage": 0.5,          # least a peer may claim, and mean it
          "max_coverage": 0.999,        # most it may claim
          "tolerance": 0.0              # slack when testing membership
        }
      }
    }

``quantity`` is the link to ``physics.json``. It is what lets a later result
for that quantity RESOLVE an outstanding prediction with no application
involvement, which is the default path (the other is
:meth:`~.audit.CalibrationAuditor.resolve`, for a truth AT never sees as a task
result). The name need not appear in a physics declaration --- with no physics
model loaded, or a quantity absent from it, the automatic path simply never
fires for it and only the explicit call resolves it.

**Why bound the claimed coverage.** A peer that may claim any coverage it likes
can pass this audit forever by advertising 0.01: sets that are almost never
required to contain anything are trivially well calibrated. ``min_coverage`` is
the operator saying "offer this capability and you are claiming at least this
much" --- honesty about one's limits is only meaningful against a floor. The
upper bound is the mirror: a claim of 1.0 asserts a set that must never miss,
which no finite sample can support and which the test would reject on the first
miss forever after.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Optional, Union

logger = logging.getLogger(__name__)

#: Environment variable naming the declaration file. Unset -> empty model.
CALIBRATION_ENV = 'AT_CALIBRATION'

#: Resolutions required before the audit will return a verdict. Thirty is not
#: a magic number; it is roughly where the exact test can reject a peer that
#: claims 0.9 and delivers 0.6, which is the kind of shortfall this layer
#: exists to catch. Below it the test is silent rather than lenient.
DEFAULT_MIN_SAMPLES = 30

#: Level of the one-sided test, i.e. the rate at which a perfectly calibrated
#: peer is wrongly accused. Deliberately conservative: this produces evidence
#: against a peer, and the cost of a false accusation is a demotion.
DEFAULT_AUDIT_ALPHA = 0.05

#: Per (peer, capability) outcome ring. Bounds the store, and gives the audit a
#: SLIDING window: a peer that was badly calibrated a year ago and has since
#: been corrected should be able to age out of the verdict.
DEFAULT_MAX_OUTCOMES = 256

#: Per (peer, quantity) outstanding-prediction ring.
DEFAULT_MAX_OUTSTANDING = 64

#: How long a prediction has to be resolved before it is discarded unscored.
DEFAULT_HORIZON_SEC = 60.0

DEFAULT_MIN_COVERAGE = 0.5
DEFAULT_MAX_COVERAGE = 0.999


class CalibrationDeclarationError(ValueError):
    """A malformed ``calibration.json``. Fatal at load."""


@dataclass(frozen=True)
class Predictive:
    """One capability declared to emit prediction sets."""

    capability: str
    quantity: str
    horizon_sec: float = DEFAULT_HORIZON_SEC
    min_coverage: float = DEFAULT_MIN_COVERAGE
    max_coverage: float = DEFAULT_MAX_COVERAGE
    tolerance: float = 0.0

    def coverage_ok(self, coverage: float) -> bool:
        return self.min_coverage <= coverage <= self.max_coverage


@dataclass(frozen=True)
class CalibrationModel:
    """A parsed ``calibration.json``."""

    capabilities: Mapping[str, Predictive] = field(default_factory=dict)
    min_samples: int = DEFAULT_MIN_SAMPLES
    audit_alpha: float = DEFAULT_AUDIT_ALPHA
    max_outcomes: int = DEFAULT_MAX_OUTCOMES
    max_outstanding: int = DEFAULT_MAX_OUTSTANDING
    #: quantity name -> the capabilities predicting it, built at load. Several
    #: capabilities may predict one quantity (two forecasters, say), so unlike
    #: the physics model's capability->quantity map this one is not injective.
    by_quantity: Mapping[str, tuple[str, ...]] = field(default_factory=dict)

    @property
    def empty(self) -> bool:
        return not self.capabilities

    def for_capability(self, capability: Optional[str]) -> Optional[Predictive]:
        if not capability:
            return None
        return self.capabilities.get(capability)

    def predicts(self, quantity: Optional[str]) -> bool:
        return bool(quantity) and quantity in self.by_quantity


#: The all-empty model: no declarations, hence no verdicts.
EMPTY_MODEL = CalibrationModel()


def _number(obj: Mapping[str, Any], key: str, default: float, where: str) -> float:
    if key not in obj or obj[key] is None:
        return default
    try:
        return float(obj[key])
    except (TypeError, ValueError):
        raise CalibrationDeclarationError(
            f'{where}: {key} must be a number, got {obj[key]!r}') from None


def parse_calibration(data: Mapping[str, Any]) -> CalibrationModel:
    """Build a :class:`CalibrationModel` from an already-decoded declaration."""
    if not isinstance(data, Mapping):
        raise CalibrationDeclarationError(
            'calibration declaration must be an object')
    version = data.get('version', 1)
    try:
        version = int(version)
    except (TypeError, ValueError):
        raise CalibrationDeclarationError(
            f'unsupported calibration declaration version {version!r}') from None
    if version != 1:
        raise CalibrationDeclarationError(
            f'unsupported calibration declaration version {version!r}')

    min_samples = int(_number(data, 'min_samples', DEFAULT_MIN_SAMPLES, 'calibration'))
    if min_samples < 1:
        raise CalibrationDeclarationError(
            f'min_samples must be at least 1, got {min_samples}')
    audit_alpha = _number(data, 'audit_alpha', DEFAULT_AUDIT_ALPHA, 'calibration')
    if not 0.0 < audit_alpha < 1.0:
        raise CalibrationDeclarationError(
            f'audit_alpha must be in (0, 1), got {audit_alpha}')
    max_outcomes = int(_number(data, 'max_outcomes', DEFAULT_MAX_OUTCOMES, 'calibration'))
    if max_outcomes < min_samples:
        # Otherwise the ring can never hold enough to reach min_samples and the
        # layer is silently inert -- exactly the failure the physics loader
        # refuses to degrade into.
        raise CalibrationDeclarationError(
            f'max_outcomes ({max_outcomes}) is below min_samples '
            f'({min_samples}), so the audit could never speak')
    max_outstanding = int(_number(data, 'max_outstanding',
                                  DEFAULT_MAX_OUTSTANDING, 'calibration'))
    if max_outstanding < 1:
        raise CalibrationDeclarationError(
            f'max_outstanding must be at least 1, got {max_outstanding}')
    default_horizon = _number(data, 'horizon_sec', DEFAULT_HORIZON_SEC, 'calibration')

    raw = data.get('capabilities', {}) or {}
    if not isinstance(raw, Mapping):
        raise CalibrationDeclarationError('capabilities must be an object')

    caps: dict[str, Predictive] = {}
    by_quantity: dict[str, list[str]] = {}
    for name, decl in raw.items():
        where = f'capability {name!r}'
        if not isinstance(decl, Mapping):
            raise CalibrationDeclarationError(f'{where}: must be an object')
        quantity = decl.get('quantity')
        if not quantity or not isinstance(quantity, str):
            raise CalibrationDeclarationError(
                f'{where}: quantity is required and must be a string')
        horizon = _number(decl, 'horizon_sec', default_horizon, where)
        if horizon <= 0.0:
            raise CalibrationDeclarationError(
                f'{where}: horizon_sec must be positive, got {horizon}')
        lo = _number(decl, 'min_coverage', DEFAULT_MIN_COVERAGE, where)
        hi = _number(decl, 'max_coverage', DEFAULT_MAX_COVERAGE, where)
        if not 0.0 < lo <= hi < 1.0:
            raise CalibrationDeclarationError(
                f'{where}: need 0 < min_coverage <= max_coverage < 1, '
                f'got {lo} and {hi}')
        tolerance = _number(decl, 'tolerance', 0.0, where)
        if tolerance < 0.0:
            raise CalibrationDeclarationError(
                f'{where}: tolerance must not be negative, got {tolerance}')
        caps[name] = Predictive(capability=name, quantity=quantity,
                                horizon_sec=horizon, min_coverage=lo,
                                max_coverage=hi, tolerance=tolerance)
        by_quantity.setdefault(quantity, []).append(name)

    return CalibrationModel(
        capabilities=caps, min_samples=min_samples, audit_alpha=audit_alpha,
        max_outcomes=max_outcomes, max_outstanding=max_outstanding,
        by_quantity={q: tuple(sorted(c)) for q, c in by_quantity.items()})


def load_calibration(path: Union[str, Path, None] = None) -> CalibrationModel:
    """Load the declaration named by ``path`` or by ``$AT_CALIBRATION``.

    Returns :data:`EMPTY_MODEL` when nothing is configured. A configured path
    that does not exist or does not parse raises: an audit an operator believes
    is running and is not is worse than one never switched on.
    """
    if path is None:
        path = os.environ.get(CALIBRATION_ENV)
    if not path:
        return EMPTY_MODEL
    p = Path(path)
    if not p.is_file():
        raise CalibrationDeclarationError(
            f'{CALIBRATION_ENV} names {p}, which is not a file')
    text = p.read_text()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        try:
            from ruamel.yaml import YAML
            data = YAML(typ='safe').load(text)
        except Exception as exc:
            raise CalibrationDeclarationError(f'{p}: cannot parse: {exc}') from None
    model = parse_calibration(data)
    logger.info('calibration: loaded %d predictive capabilities from %s',
                len(model.capabilities), p)
    return model
