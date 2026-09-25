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
"""The ``prequential.json`` declaration: which forecasts are scored, and how.

The *domain* half of R+D.md §12.5, on the same pattern as ``physics.json``,
``certificates.json`` and ``calibration.json``: :mod:`.scoring` owns the
arithmetic and cannot be overridden by an operator; this file says which
capability forecasts, which declared quantity the forecast is about, at what
level it is scored, what a unit of loss means in that quantity's units, and
how far the learned weight may move.

Set ``AT_PREQUENTIAL`` to a declaration path to turn the layer on. With
nothing set, :func:`load_prequential` returns an EMPTY model and every
competence multiplier is exactly 1.0 --- the authored ``transaction_weight``,
verbatim --- so the mechanism is inert until a scenario opts in. Same default
as the other three oracle layers, and for the same reason: a learned weight
nobody asked for is a change to the reputation algebra nobody asked for.

Schema (version 1)::

    {
      "version": 1,
      "min_samples": 8,          # resolutions before the weight moves at all
      "max_outcomes": 64,        # per (peer, capability); ring bound
      "max_outstanding": 32,     # unresolved forecasts per quantity
      "horizon_sec": 60.0,       # default deadline for a forecast to resolve
      "eta": 1.0,                # Hedge learning rate (aggregation half)
      "weight_band": {"min": 0.5, "max": 2.0},
      "capabilities": {
        "fc.thermal": {
          "quantity": "sat.bus-temp",  # what the forecast is ABOUT
          "scale": 20.0,               # one unit of loss, in the quantity's unit
          "alpha": 0.1,                # the level the interval score uses
          "horizon_sec": 120.0,        # overrides the model default
          "tolerance": 0.0             # slack on the observed outcome
        }
      }
    }

``quantity`` is the link to ``physics.json``, exactly as in §12.4: it is what
lets a later result for that quantity resolve an outstanding forecast with no
application involvement. ``resolve()`` is the explicit override.

**Why ``alpha`` is declared and not read off the peer's prediction.** The
interval score's miss penalty is ``2/alpha``, so a peer allowed to pick its own
level lowers it to make misses cheap and keeps its intervals narrow. It would
also make competence incomparable: two peers scored at different levels are not
being scored on the same rule, and both the weighting and the regret bound
depend on there being one. What the peer *claims* about its coverage is §12.4's
business, where it is bounded and audited.

**Why the band must contain 1.0.** The authored ``transaction_weight`` is the
anchor (doc/architecture/prequential-competence.md): learned competence moves
the weight within the range the operator allowed and never outside it. A band
that excludes 1.0 would make the operator's own number unreachable, so it is
refused at load rather than discovered as a puzzle in a log.
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
PREQUENTIAL_ENV = 'AT_PREQUENTIAL'

#: Resolved forecasts required before the multiplier leaves 1.0. Smaller than
#: the coverage audit's 30 because this is a MEAN and not a hypothesis test: a
#: handful of resolutions is a usable estimate of typical sharpness, where the
#: same handful cannot reject a coverage claim. Below it the weight does not
#: move, which is silence rather than a guess.
DEFAULT_MIN_SAMPLES = 8

#: Per (peer, capability) loss ring. Bounds the store and makes the multiplier
#: a SLIDING window: a peer that forecast badly a year ago and has since been
#: corrected ages out of it. Matches the C twin's AT_PREQ_MAX_OUTCOMES.
DEFAULT_MAX_OUTCOMES = 64

#: Per-quantity outstanding-forecast ring, across all peers.
DEFAULT_MAX_OUTSTANDING = 32

#: How long a forecast has to be resolved before it is discarded unscored.
DEFAULT_HORIZON_SEC = 60.0

#: Hedge learning rate. The regret bound's two terms trade off at
#: ``sqrt(8 ln N / T)``, so an operator that knows its horizon can tune this;
#: 1.0 is the anytime choice for the run lengths a mesh actually sees.
DEFAULT_ETA = 1.0

#: The level the interval score is taken at, i.e. the 90% interval.
DEFAULT_ALPHA = 0.1

#: How far the learned multiplier may move the authored weight.
DEFAULT_BAND_MIN = 0.5
DEFAULT_BAND_MAX = 2.0


class PrequentialDeclarationError(ValueError):
    """A malformed ``prequential.json``. Fatal at load."""


@dataclass(frozen=True)
class Forecasting:
    """One capability whose replies carry a scored forecast."""

    capability: str
    quantity: str
    scale: float
    alpha: float = DEFAULT_ALPHA
    horizon_sec: float = DEFAULT_HORIZON_SEC
    tolerance: float = 0.0


@dataclass(frozen=True)
class PrequentialModel:
    """A parsed ``prequential.json``."""

    capabilities: Mapping[str, Forecasting] = field(default_factory=dict)
    min_samples: int = DEFAULT_MIN_SAMPLES
    max_outcomes: int = DEFAULT_MAX_OUTCOMES
    max_outstanding: int = DEFAULT_MAX_OUTSTANDING
    eta: float = DEFAULT_ETA
    band_min: float = DEFAULT_BAND_MIN
    band_max: float = DEFAULT_BAND_MAX
    #: quantity -> the capabilities forecasting it, built at load. Several
    #: capabilities may forecast one quantity (two forecasters), so this is
    #: not injective.
    by_quantity: Mapping[str, tuple[str, ...]] = field(default_factory=dict)

    @property
    def empty(self) -> bool:
        return not self.capabilities

    def for_capability(self, capability: Optional[str]) -> Optional[Forecasting]:
        if not capability:
            return None
        return self.capabilities.get(capability)

    def forecasts(self, quantity: Optional[str]) -> bool:
        return bool(quantity) and quantity in self.by_quantity


#: The all-empty model: no declarations, hence no learned weights.
EMPTY_MODEL = PrequentialModel()


def _number(obj: Mapping[str, Any], key: str, default: float,
            where: str) -> float:
    if key not in obj or obj[key] is None:
        return default
    try:
        return float(obj[key])
    except (TypeError, ValueError):
        raise PrequentialDeclarationError(
            f'{where}: {key} must be a number, got {obj[key]!r}') from None


def parse_prequential(data: Mapping[str, Any]) -> PrequentialModel:
    """Build a :class:`PrequentialModel` from an already-decoded declaration."""
    if not isinstance(data, Mapping):
        raise PrequentialDeclarationError(
            'prequential declaration must be an object')
    version = data.get('version', 1)
    try:
        version = int(version)
    except (TypeError, ValueError):
        raise PrequentialDeclarationError(
            f'unsupported prequential declaration version '
            f'{version!r}') from None
    if version != 1:
        raise PrequentialDeclarationError(
            f'unsupported prequential declaration version {version!r}')

    min_samples = int(_number(data, 'min_samples', DEFAULT_MIN_SAMPLES,
                              'prequential'))
    if min_samples < 1:
        raise PrequentialDeclarationError(
            f'min_samples must be at least 1, got {min_samples}')
    max_outcomes = int(_number(data, 'max_outcomes', DEFAULT_MAX_OUTCOMES,
                               'prequential'))
    if max_outcomes < min_samples:
        # Otherwise the ring can never hold enough to reach min_samples and
        # the layer is silently inert -- the same refusal the coverage audit's
        # loader makes.
        raise PrequentialDeclarationError(
            f'max_outcomes ({max_outcomes}) is below min_samples '
            f'({min_samples}), so the weight could never move')
    max_outstanding = int(_number(data, 'max_outstanding',
                                  DEFAULT_MAX_OUTSTANDING, 'prequential'))
    if max_outstanding < 1:
        raise PrequentialDeclarationError(
            f'max_outstanding must be at least 1, got {max_outstanding}')
    eta = _number(data, 'eta', DEFAULT_ETA, 'prequential')
    if not eta > 0.0:
        raise PrequentialDeclarationError(f'eta must be positive, got {eta}')
    default_horizon = _number(data, 'horizon_sec', DEFAULT_HORIZON_SEC,
                              'prequential')
    if not default_horizon > 0.0:
        raise PrequentialDeclarationError(
            f'horizon_sec must be positive, got {default_horizon}')

    band = data.get('weight_band') or {}
    if not isinstance(band, Mapping):
        raise PrequentialDeclarationError('weight_band must be an object')
    band_min = _number(band, 'min', DEFAULT_BAND_MIN, 'weight_band')
    band_max = _number(band, 'max', DEFAULT_BAND_MAX, 'weight_band')
    if not 0.0 < band_min <= 1.0 <= band_max:
        # The authored transaction_weight is the anchor, so it has to be
        # inside the band. A band that excludes 1.0 makes the operator's own
        # number unreachable.
        raise PrequentialDeclarationError(
            f'weight_band must satisfy 0 < min <= 1 <= max, got {band_min} '
            f'and {band_max}')

    raw = data.get('capabilities', {}) or {}
    if not isinstance(raw, Mapping):
        raise PrequentialDeclarationError('capabilities must be an object')

    caps: dict[str, Forecasting] = {}
    by_quantity: dict[str, list[str]] = {}
    for name, decl in raw.items():
        where = f'capability {name!r}'
        if not isinstance(decl, Mapping):
            raise PrequentialDeclarationError(f'{where}: must be an object')
        quantity = decl.get('quantity')
        if not quantity or not isinstance(quantity, str):
            raise PrequentialDeclarationError(
                f'{where}: quantity is required and must be a string')
        if 'scale' not in decl or decl['scale'] is None:
            # No default is defensible: the scale is what makes a loss in the
            # quantity's units comparable to a loss in another's, and a
            # guessed one would silently decide how much a metre matters.
            raise PrequentialDeclarationError(
                f'{where}: scale is required (one unit of loss, in the '
                f'quantity\'s units)')
        scale = _number(decl, 'scale', 0.0, where)
        if not scale > 0.0:
            raise PrequentialDeclarationError(
                f'{where}: scale must be positive, got {scale}')
        alpha = _number(decl, 'alpha', DEFAULT_ALPHA, where)
        if not 0.0 < alpha < 1.0:
            raise PrequentialDeclarationError(
                f'{where}: alpha must be in (0, 1), got {alpha}')
        horizon = _number(decl, 'horizon_sec', default_horizon, where)
        if horizon <= 0.0:
            raise PrequentialDeclarationError(
                f'{where}: horizon_sec must be positive, got {horizon}')
        tolerance = _number(decl, 'tolerance', 0.0, where)
        if tolerance < 0.0:
            raise PrequentialDeclarationError(
                f'{where}: tolerance must not be negative, got {tolerance}')
        # Every capability forecasting ONE quantity must be scored at one
        # level and on one scale. Refused here rather than tie-broken at
        # runtime: the aggregate forecast is a single interval, so it has to
        # have a single alpha; and the mixture loss adds peers' losses
        # together, which means nothing if they are divided by different
        # scales. Two peers scored at different levels for the same quantity
        # are not being compared, which is the same argument that makes alpha
        # the operator's to declare in the first place.
        for other in caps.values():
            if other.quantity != quantity:
                continue
            if other.alpha != alpha or other.scale != scale:
                raise PrequentialDeclarationError(
                    f'{where}: forecasts {quantity!r} at alpha={alpha} '
                    f'scale={scale}, but {other.capability!r} forecasts it at '
                    f'alpha={other.alpha} scale={other.scale}; capabilities '
                    f'sharing a quantity must share both')
        caps[name] = Forecasting(capability=name, quantity=quantity,
                                 scale=scale, alpha=alpha,
                                 horizon_sec=horizon, tolerance=tolerance)
        by_quantity.setdefault(quantity, []).append(name)

    return PrequentialModel(
        capabilities=caps, min_samples=min_samples, max_outcomes=max_outcomes,
        max_outstanding=max_outstanding, eta=eta, band_min=band_min,
        band_max=band_max,
        by_quantity={q: tuple(sorted(c)) for q, c in by_quantity.items()})


def load_prequential(path: Union[str, Path, None] = None) -> PrequentialModel:
    """Load the declaration named by ``path`` or by ``$AT_PREQUENTIAL``.

    Returns :data:`EMPTY_MODEL` when nothing is configured. A configured path
    that does not exist or does not parse raises: a learned weighting an
    operator believes is running and is not is worse than one never switched
    on, because the EMA it silently fails to move is the one the operator was
    counting on.
    """
    if path is None:
        path = os.environ.get(PREQUENTIAL_ENV)
    if not path:
        return EMPTY_MODEL
    p = Path(path)
    if not p.is_file():
        raise PrequentialDeclarationError(
            f'{PREQUENTIAL_ENV} names {p}, which is not a file')
    text = p.read_text()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        try:
            from ruamel.yaml import YAML
            data = YAML(typ='safe').load(text)
        except Exception as exc:
            raise PrequentialDeclarationError(
                f'{p}: cannot parse: {exc}') from None
    model = parse_prequential(data)
    logger.info('prequential: loaded %d forecasting capabilities from %s',
                len(model.capabilities), p)
    return model
