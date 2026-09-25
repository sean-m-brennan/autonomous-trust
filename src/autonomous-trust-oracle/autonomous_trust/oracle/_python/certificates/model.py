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
"""``certificates.json``: which capabilities certify, and with which checker.

R+D.md §12.3. The declaration says, per capability, that its answers arrive
with a witness and which checker verifies that witness --- or says explicitly
that they do not, which is the other half of the point. The oracle doc asks
that "a capability whose result cannot be certified should be recognized as the
expensive case rather than treated as the normal one", and a capability can
only be *recognized* as that if someone wrote it down.

Three states, and the difference between the second and third is the whole
design:

``checker: <kind>``
    Answers carry a witness of that kind. Verified exactly; a valid witness is
    proof the answer is right, an invalid one is proof it is wrong.
``checker: null``
    Declared UNCERTIFIABLE. No verdict is ever produced, the existing
    completion arms score it as before --- and it appears in the inventory as
    an acknowledged expensive case.
absent from the file
    Nobody has considered it. Also no verdict, but it is an *unexamined*
    capability rather than an examined one, and the inventory says so.

Canonical form is JSON, one file for both runtimes --- the arrangement
``doc/architecture/trust-tiers.md`` §8 settled for the trust ladder and
``physics.json`` reused for R+D.md §12.2. ``AT_CERTIFICATES`` names it; with
nothing set the model is empty and the layer is inert.

Schema (version 1)::

    {
      "version": 1,
      "capabilities": {
        "demo.matmul":  {"checker": "matrix_product", "required": true,
                         "repetitions": 4},
        "demo.route":   {"checker": "path", "required": true},
        "demo.solve":   {"checker": "linear_solve", "tolerance": 1e-6},
        "demo.opinion": {"checker": null,
                         "note": "no witness exists for a judgement call"}
      }
    }

``required`` (default true when a checker is named) is what makes an ABSENT
witness evidence rather than a shrug: a capability declared to certify and
answering without a certificate has not done what it said it would. Set it
false while a domain is being migrated, and a missing witness falls through to
the completion arm instead.

Parameters are a fixed, flat set rather than a free-form blob, because the C
twin holds them in a struct and a parameter one runtime honours and the other
ignores is a verdict divergence waiting to happen. Each checker documents which
it reads; the rest are simply unused.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Optional, Union

logger = logging.getLogger(__name__)

#: Environment variable naming the declaration file. Unset -> empty model.
CERTIFICATES_ENV = 'AT_CERTIFICATES'

#: The closed set of checker kinds, in the order the oracle doc tabulates them
#: (doc/verification_oracle.md, "Certificates: exploit verification
#: asymmetry"). Closed for the same reason the evidence channels are: an
#: unknown spelling is refused, never silently treated as "no checker", because
#: a typo that turns a certified capability into an unchecked one is exactly
#: the failure this layer exists to prevent. Adding a kind is a deliberate edit
#: here AND in the C twin's checker table.
CHECKER_KINDS: tuple[str, ...] = (
    'lp',                 #: constrained optimization: primal + dual, or Farkas
    'sat',                #: satisfying assignment, or a DRAT refutation
    'path',               #: a path plus a feasible potential (its LP dual)
    'linear_solve',       #: residual norm of A x - b
    'matrix_product',     #: Freivalds; the witness is the challenge, not data
    'schedule',           #: a schedule plus its makespan witness
    'flow',               #: a flow plus a min-cut witness
    'state_estimation',   #: an innovation sequence, whiteness-bounded
)

#: Default numeric slack for every comparison a checker makes. Deliberately
#: tight: a certificate is meant to be exact, and a domain that needs a looser
#: bound should say so in its declaration rather than inherit one.
DEFAULT_TOLERANCE = 1e-9


class CertificateDeclarationError(ValueError):
    """A malformed ``certificates.json``. Fatal at load."""


@dataclass(frozen=True)
class CertifiedCapability:
    """One capability's certification contract.

    ``checker`` is None for a capability declared uncertifiable --- an
    acknowledged expensive case, which is a different and more useful state
    than not being mentioned at all.
    """

    name: str
    checker: Optional[str] = None
    required: bool = True
    note: str = ''
    tolerance: float = DEFAULT_TOLERANCE
    repetitions: int = 3          #: matrix_product: Freivalds rounds
    require_optimal: bool = True  #: path, flow: is optimality claimed too
    max_lag: int = 5              #: state_estimation: autocorrelation lags
    bound: float = 0.2            #: state_estimation: |rho_k| bound
    max_proof_len: int = 100000   #: sat: DRAT lemma cap

    @property
    def certifiable(self) -> bool:
        return self.checker is not None


@dataclass(frozen=True)
class CertificateModel:
    """A parsed ``certificates.json``."""

    capabilities: Mapping[str, CertifiedCapability] = None

    def __post_init__(self):
        if self.capabilities is None:
            object.__setattr__(self, 'capabilities', {})

    @property
    def empty(self) -> bool:
        return not self.capabilities

    def for_capability(self, name: Optional[str]) -> Optional[CertifiedCapability]:
        if not name:
            return None
        return self.capabilities.get(name)


#: The all-empty model: nothing declared, hence no verdicts. The default
#: everywhere, so the layer is inert until a scenario opts in.
EMPTY_MODEL = CertificateModel()


def _num(spec: Mapping[str, Any], key: str, default, where: str, cast=float):
    if key not in spec or spec[key] is None:
        return default
    try:
        if cast is int and isinstance(spec[key], bool):
            raise TypeError
        return cast(spec[key])
    except (TypeError, ValueError):
        raise CertificateDeclarationError(
            f'{where}: {key} must be a number, got {spec[key]!r}') from None


def parse_certificates(data: Mapping[str, Any]) -> CertificateModel:
    """Build a :class:`CertificateModel` from an already-decoded declaration."""
    if not isinstance(data, Mapping):
        raise CertificateDeclarationError(
            'certificate declaration must be an object')
    version = data.get('version', 1)
    try:
        version = int(version)
    except (TypeError, ValueError):
        raise CertificateDeclarationError(
            f'unsupported declaration version {version!r}') from None
    if version != 1:
        raise CertificateDeclarationError(
            f'unsupported declaration version {version!r}')

    raw = data.get('capabilities') or {}
    if not isinstance(raw, Mapping):
        raise CertificateDeclarationError('"capabilities" must be an object')

    caps: dict[str, CertifiedCapability] = {}
    for name, spec in raw.items():
        where = f'capability {name!r}'
        if not isinstance(spec, Mapping):
            raise CertificateDeclarationError(f'{where}: must be an object')
        checker = spec.get('checker')
        if checker is not None:
            if not isinstance(checker, str) or checker not in CHECKER_KINDS:
                # Refused, never degraded to "uncertifiable": a typo that
                # quietly turned a certified capability into an unchecked one
                # would be the worst possible failure of this layer, and it
                # would look exactly like a deliberate `null`.
                raise CertificateDeclarationError(
                    f'{where}: unknown checker {checker!r}; known kinds are '
                    f'{", ".join(CHECKER_KINDS)} (or null for a capability '
                    f'that cannot be certified)')
        required = spec.get('required', True)
        if not isinstance(required, bool):
            raise CertificateDeclarationError(
                f'{where}: "required" must be true or false')
        note = spec.get('note') or ''
        if not isinstance(note, str):
            raise CertificateDeclarationError(f'{where}: "note" must be a string')

        tolerance = _num(spec, 'tolerance', DEFAULT_TOLERANCE, where)
        if tolerance < 0:
            raise CertificateDeclarationError(f'{where}: tolerance must be >= 0')
        repetitions = _num(spec, 'repetitions', 3, where, int)
        if repetitions < 1:
            raise CertificateDeclarationError(f'{where}: repetitions must be >= 1')
        max_lag = _num(spec, 'max_lag', 5, where, int)
        if max_lag < 1:
            raise CertificateDeclarationError(f'{where}: max_lag must be >= 1')
        bound = _num(spec, 'bound', 0.2, where)
        if bound < 0:
            raise CertificateDeclarationError(f'{where}: bound must be >= 0')
        max_proof_len = _num(spec, 'max_proof_len', 100000, where, int)
        if max_proof_len < 1:
            raise CertificateDeclarationError(f'{where}: max_proof_len must be >= 1')
        require_optimal = spec.get('require_optimal', True)
        if not isinstance(require_optimal, bool):
            raise CertificateDeclarationError(
                f'{where}: "require_optimal" must be true or false')

        caps[name] = CertifiedCapability(
            name=name, checker=checker, required=required, note=note,
            tolerance=tolerance, repetitions=repetitions,
            require_optimal=require_optimal, max_lag=max_lag, bound=bound,
            max_proof_len=max_proof_len)

    return CertificateModel(capabilities=caps)


def load_certificates(path: Union[str, Path, None] = None) -> CertificateModel:
    """Load the declaration named by ``path`` or by ``$AT_CERTIFICATES``.

    Returns :data:`EMPTY_MODEL` when nothing is configured. A configured path
    that does not exist or does not parse raises: a verification layer that
    quietly stopped verifying is worse than one that was never turned on,
    because the operator believes the answers are being checked.
    """
    if path is None:
        path = os.environ.get(CERTIFICATES_ENV)
    if not path:
        return EMPTY_MODEL
    p = Path(path)
    if not p.is_file():
        raise CertificateDeclarationError(
            f'{CERTIFICATES_ENV} names {p}, which is not a file')
    text = p.read_text()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        try:
            from ruamel.yaml import YAML
            data = YAML(typ='safe').load(text)
        except Exception as exc:
            raise CertificateDeclarationError(
                f'{p}: cannot parse: {exc}') from None
    model = parse_certificates(data)
    logger.info('certificates: loaded %d capability declarations from %s',
                len(model.capabilities), p)
    return model
