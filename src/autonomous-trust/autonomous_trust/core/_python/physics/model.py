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
"""The ``physics.json`` declaration: what a capability reports, and its bounds.

This is the *domain* half of R+D.md §12.2. :mod:`.units` owns the axioms --- what
a newton is --- and cannot be overridden; this file says which capability
reports which physical quantity, what range and rate that quantity is capable
of, and which linear conservation relations tie several quantities together.
The split is deliberate: an operator who could redefine the units could refute
any peer by declaration.

**A separate file from the trust ladder, on purpose.** The ladder answers "how
much does this capability count and who may run it"; this answers "what does
its answer mean". They are read by different code at different times and a
scenario may well want one without the other. Canonical form is JSON, for the
same reason the ladder's is (doc/architecture/trust-tiers.md §8): one file feeds
both runtimes --- this loader and the C twin's jansson parser in
``src/c/autonomous_trust/physics/physics.c`` --- with no conversion step and
nothing to drift. YAML is a superset of JSON, so a scenario may write ``.yaml``
if it only ever feeds this loader.

Set ``AT_PHYSICS`` to a declaration path to turn the layer on. With nothing
set, :func:`load_physics` returns an EMPTY model and every check returns "no
verdict", so the mechanism is inert until a scenario opts in. That default is
load-bearing: a physical refutation is the hardest evidence AT produces
(:data:`~..reputation.TX_CHANNEL_PHYSICAL`, weight 3), and a checker that
guessed at undeclared quantities would be manufacturing it.

Schema (version 1)::

    {
      "version": 1,
      "window_sec": 60.0,          # how long an observation stays comparable
      "max_observations": 64,      # per quantity, per peer; ring bound
      "quantities": {
        "sat.bus-power": {
          "capability": "sat.power-report",   # which capability reports it
          "unit": "W",                        # the declared unit
          "min": 0.0, "max": 2000.0,          # in the DECLARED unit
          "max_rate": 250.0,                  # |dv/dt| bound, unit per second
          "max_accel": 100.0,                 # |d2v/dt2| bound, optional
          "tolerance": 5.0,                   # interval half-width for the
                                              # set-membership intersection
          "components": 1                     # 3 for a position, say
        }
      },
      "relations": [
        { "name": "power-balance",
          "terms": {"sat.solar-power": 1.0,
                    "sat.load-power": -1.0,
                    "sat.batt-charge-rate": -1.0},
          "constant": 0.0,
          "tolerance": 2.0,
          "window_sec": 5.0 }
      ]
    }

Every field but ``capability`` is optional; an omitted bound is simply not
checked. A relation is the parity-relation form from the aerospace
fault-detection tradition (Isermann; Blanke et al.), restricted to the linear
case::

    r = constant + sum(coefficient * value_in_SI)

which vanishes under consistency and does not under a fault. Linear is not a
shortcut --- conservation of mass, energy, momentum and charge are all sums of
signed flows --- and it is what lets the residual be computed identically in
two languages with no expression evaluator to keep in step.

Declarations are validated at load: an unknown unit, a relation naming an
undeclared quantity, or a relation whose terms are not all of the SAME
dimension raises :class:`PhysicsDeclarationError`. That last one is the check
that makes a relation meaningful; adding a power to a temperature has no
residual worth computing, and catching it at load is the difference between an
operator error and a peer wrongly refuted.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Optional, Union

from .units import Dimension, UnitError, parse_unit

logger = logging.getLogger(__name__)

#: Environment variable naming the declaration file. Unset -> empty model.
PHYSICS_ENV = 'AT_PHYSICS'

#: Default observation window, seconds. An observation older than this is not
#: comparable with a fresh one: peers legitimately disagree about a quantity
#: that has moved on, and calling that a conflict would refute honest peers.
DEFAULT_WINDOW_SEC = 60.0

#: Per-quantity, per-peer ring size. Bounds the store in a long-running node;
#: only the last two observations are needed for rate and acceleration.
DEFAULT_MAX_OBSERVATIONS = 64


class PhysicsDeclarationError(ValueError):
    """A malformed or incoherent ``physics.json``. Fatal at load."""


@dataclass(frozen=True)
class Quantity:
    """One declared physical quantity and the bounds it is capable of.

    Bounds are stated in the DECLARED unit and converted to SI once, here, so
    that everything downstream --- the store, the residuals, the intervals ---
    is in one coherent system and a peer reporting kilowatts is compared with
    a peer reporting watts on equal terms.
    """

    name: str
    capability: str
    unit: str = ''
    dimension: Dimension = field(default_factory=lambda: parse_unit(''))
    minimum: Optional[float] = None
    maximum: Optional[float] = None
    max_rate: Optional[float] = None
    max_accel: Optional[float] = None
    tolerance: float = 0.0
    components: int = 1

    @property
    def si_minimum(self) -> Optional[float]:
        return None if self.minimum is None else self.dimension.to_si(self.minimum)

    @property
    def si_maximum(self) -> Optional[float]:
        return None if self.maximum is None else self.dimension.to_si(self.maximum)

    @property
    def si_max_rate(self) -> Optional[float]:
        # A RATE is a difference per second, so the offset cancels and only
        # the scale applies. Using to_si() here would add 273.15 K/s to every
        # Celsius rate bound -- the sort of error the affine-unit refusal in
        # units.py exists to make loud elsewhere.
        return (None if self.max_rate is None
                else self.max_rate * self.dimension.scale)

    @property
    def si_max_accel(self) -> Optional[float]:
        return (None if self.max_accel is None
                else self.max_accel * self.dimension.scale)

    @property
    def si_tolerance(self) -> float:
        # Likewise a half-WIDTH, not a point: scale only.
        return self.tolerance * self.dimension.scale


@dataclass(frozen=True)
class Relation:
    """A linear parity relation: ``constant + sum(coeff * value)`` ~ 0.

    ``window_sec`` is how fresh every contributing observation must be for the
    residual to mean anything. It defaults to the model window but is usually
    tighter: a conservation law holds instantaneously, and evaluating it over
    stale terms invents violations out of ordinary change.
    """

    name: str
    terms: tuple[tuple[str, float], ...]
    constant: float = 0.0
    tolerance: float = 0.0
    window_sec: Optional[float] = None


@dataclass(frozen=True)
class PhysicsModel:
    """A parsed ``physics.json``: quantities, relations, and window policy."""

    quantities: Mapping[str, Quantity] = field(default_factory=dict)
    relations: tuple[Relation, ...] = ()
    window_sec: float = DEFAULT_WINDOW_SEC
    max_observations: int = DEFAULT_MAX_OBSERVATIONS
    #: capability name -> quantity name, built at load. A capability reports
    #: at most one quantity; two quantities claiming one capability is a
    #: declaration error, because the checker would have no way to choose.
    by_capability: Mapping[str, str] = field(default_factory=dict)

    @property
    def empty(self) -> bool:
        return not self.quantities

    def for_capability(self, capability: Optional[str]) -> Optional[Quantity]:
        if not capability:
            return None
        name = self.by_capability.get(capability)
        return None if name is None else self.quantities[name]

    def relations_for(self, quantity_name: str) -> tuple[Relation, ...]:
        """Relations in which ``quantity_name`` appears as a term."""
        return tuple(r for r in self.relations
                     if any(q == quantity_name for q, _ in r.terms))


#: The all-empty model: no declarations, hence no verdicts. Returned whenever
#: the layer is not configured, which is the default everywhere.
EMPTY_MODEL = PhysicsModel()


def _opt_float(obj: Mapping[str, Any], key: str, where: str) -> Optional[float]:
    if key not in obj or obj[key] is None:
        return None
    try:
        return float(obj[key])
    except (TypeError, ValueError):
        raise PhysicsDeclarationError(
            f'{where}: {key} must be a number, got {obj[key]!r}') from None


def parse_physics(data: Mapping[str, Any]) -> PhysicsModel:
    """Build a :class:`PhysicsModel` from an already-decoded declaration."""
    if not isinstance(data, Mapping):
        raise PhysicsDeclarationError('physics declaration must be an object')
    version = data.get('version', 1)
    if int(version) != 1:
        raise PhysicsDeclarationError(
            f'unsupported physics declaration version {version!r}')

    window_sec = float(data.get('window_sec', DEFAULT_WINDOW_SEC))
    if window_sec <= 0:
        raise PhysicsDeclarationError('window_sec must be positive')
    max_obs = int(data.get('max_observations', DEFAULT_MAX_OBSERVATIONS))
    if max_obs < 2:
        # Rate needs two samples and acceleration three; refusing a store too
        # small to hold them is better than silently never checking a rate.
        raise PhysicsDeclarationError('max_observations must be at least 2')

    quantities: dict[str, Quantity] = {}
    by_capability: dict[str, str] = {}
    raw_q = data.get('quantities') or {}
    if not isinstance(raw_q, Mapping):
        raise PhysicsDeclarationError('"quantities" must be an object')
    for name, spec in raw_q.items():
        where = f'quantity {name!r}'
        if not isinstance(spec, Mapping):
            raise PhysicsDeclarationError(f'{where}: must be an object')
        capability = spec.get('capability')
        if not capability or not isinstance(capability, str):
            raise PhysicsDeclarationError(
                f'{where}: "capability" is required (it is how a task result '
                f'is matched to a quantity)')
        if capability in by_capability:
            raise PhysicsDeclarationError(
                f'{where}: capability {capability!r} is already reported by '
                f'quantity {by_capability[capability]!r}; a capability may '
                f'report only one quantity')
        unit = spec.get('unit') or ''
        try:
            dimension = parse_unit(unit)
        except UnitError as exc:
            raise PhysicsDeclarationError(f'{where}: {exc}') from None
        components = int(spec.get('components', 1))
        if components < 1:
            raise PhysicsDeclarationError(f'{where}: components must be >= 1')
        minimum = _opt_float(spec, 'min', where)
        maximum = _opt_float(spec, 'max', where)
        if minimum is not None and maximum is not None and minimum > maximum:
            raise PhysicsDeclarationError(
                f'{where}: min {minimum} exceeds max {maximum}')
        for key in ('max_rate', 'max_accel', 'tolerance'):
            val = _opt_float(spec, key, where)
            if val is not None and val < 0:
                raise PhysicsDeclarationError(f'{where}: {key} must be >= 0')
        quantities[name] = Quantity(
            name=name, capability=capability, unit=unit, dimension=dimension,
            minimum=minimum, maximum=maximum,
            max_rate=_opt_float(spec, 'max_rate', where),
            max_accel=_opt_float(spec, 'max_accel', where),
            tolerance=_opt_float(spec, 'tolerance', where) or 0.0,
            components=components)
        by_capability[capability] = name

    relations: list[Relation] = []
    raw_r = data.get('relations') or []
    if not isinstance(raw_r, (list, tuple)):
        raise PhysicsDeclarationError('"relations" must be a list')
    for idx, spec in enumerate(raw_r):
        rname = (spec.get('name') if isinstance(spec, Mapping) else None) \
            or f'relation[{idx}]'
        where = f'relation {rname!r}'
        if not isinstance(spec, Mapping):
            raise PhysicsDeclarationError(f'{where}: must be an object')
        raw_terms = spec.get('terms') or {}
        if not isinstance(raw_terms, Mapping) or not raw_terms:
            raise PhysicsDeclarationError(f'{where}: "terms" must be a '
                                          f'non-empty object')
        terms: list[tuple[str, float]] = []
        ref_dim: Optional[Dimension] = None
        for qname, coeff in raw_terms.items():
            if qname not in quantities:
                raise PhysicsDeclarationError(
                    f'{where}: term names undeclared quantity {qname!r}')
            try:
                terms.append((qname, float(coeff)))
            except (TypeError, ValueError):
                raise PhysicsDeclarationError(
                    f'{where}: coefficient for {qname!r} must be a number, '
                    f'got {coeff!r}') from None
            if quantities[qname].components != 1:
                # A parity relation sums scalars. A vector quantity would need
                # a relation per component and a rule for which components
                # pair up, which is more model than this form carries -- and
                # guessing it would produce residuals nobody declared.
                raise PhysicsDeclarationError(
                    f'{where}: term {qname!r} has '
                    f'{quantities[qname].components} components; a parity '
                    f'relation is over scalar quantities')
            dim = quantities[qname].dimension
            if ref_dim is None:
                ref_dim = dim
            elif not ref_dim.same_dimension(dim):
                # The check that makes the residual mean anything. Summing a
                # power and a temperature has no physical content, and finding
                # that out at load time is the difference between an operator
                # error and a peer refuted by arithmetic on nonsense.
                raise PhysicsDeclarationError(
                    f'{where}: term {qname!r} has dimension {dim} but the '
                    f'relation is over {ref_dim}; every term of a parity '
                    f'relation must share one dimension')
        # Terms are sorted so the residual sums in a fixed order: floating
        # point addition is not associative, and the two runtimes must agree
        # on the last bit of a residual that is being compared to a tolerance.
        terms.sort(key=lambda t: t[0])
        rel_window = _opt_float(spec, 'window_sec', where)
        if rel_window is not None and rel_window <= 0:
            raise PhysicsDeclarationError(f'{where}: window_sec must be > 0')
        tol = _opt_float(spec, 'tolerance', where) or 0.0
        if tol < 0:
            raise PhysicsDeclarationError(f'{where}: tolerance must be >= 0')
        relations.append(Relation(
            name=rname, terms=tuple(terms),
            constant=_opt_float(spec, 'constant', where) or 0.0,
            tolerance=tol, window_sec=rel_window))

    return PhysicsModel(quantities=quantities, relations=tuple(relations),
                        window_sec=window_sec, max_observations=max_obs,
                        by_capability=by_capability)


def load_physics(path: Union[str, Path, None] = None) -> PhysicsModel:
    """Load the declaration named by ``path`` or by ``$AT_PHYSICS``.

    Returns :data:`EMPTY_MODEL` when nothing is configured --- the layer is
    opt-in, see the module docstring. A configured path that does not exist or
    does not parse is an operator error and raises, rather than degrading
    silently to "check nothing": a physics layer that quietly stopped checking
    is worse than one that was never turned on, because the operator believes
    the claims are being verified.
    """
    if path is None:
        path = os.environ.get(PHYSICS_ENV)
    if not path:
        return EMPTY_MODEL
    p = Path(path)
    if not p.is_file():
        raise PhysicsDeclarationError(
            f'{PHYSICS_ENV} names {p}, which is not a file')
    text = p.read_text()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        # YAML is a superset of JSON; a scenario-local .yaml ladder is allowed
        # for the same reason the trust ladder allows one, but the canonical
        # cross-runtime form stays JSON because the C twin reads only that.
        try:
            from ruamel.yaml import YAML
            data = YAML(typ='safe').load(text)
        except Exception as exc:
            raise PhysicsDeclarationError(f'{p}: cannot parse: {exc}') from None
    model = parse_physics(data)
    logger.info('physics: loaded %d quantities, %d relations from %s',
                len(model.quantities), len(model.relations), p)
    return model
