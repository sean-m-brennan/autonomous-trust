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
"""The replication declaration: per-capability sampling probabilities (R+D.md §12.6).

Schema (version 1)::

    {
      "version": 1,
      "default_prob": 0.05,
      "capabilities": {
        "demo.command-issue": {"replicate_prob": 0.5},
        "demo.query":         {"replicate_prob": 0.0}
      }
    }

**The operator's number is the anchor**, as everywhere else in the verification
oracle. The doc's guidance is to "scale replication to consequence, not
uniformly" -- a ``tier 4`` ``command-issue``-class task warrants replication a
routine query does not -- and the natural scaling parameter is the capability
weight the operator already authors in ``trust_ladder.json``. This layer does
not *derive* the probability from that weight, though: a derived number would
decide, opaquely, how much a peer is watched, and the operator setting
``replicate_prob`` per capability in proportion to consequence is the same
authored-anchor discipline the ``transaction_weight`` and the calibration level
follow. ``default_prob`` covers a capability the declaration does not name.

**A closed, validated declaration.** Probabilities are checked into ``[0, 1]``
on load rather than clamped silently, for the same reason the other layers
refuse an unknown channel: a declaration is authored once and a bad number in
it is a mistake to surface, not to paper over. (A per-task *override* is a
different thing and :func:`~.sampling.clamp_prob` forgives it, because that one
arrives at runtime.)

The C twin is ``src/c/extensions/replication/replication.c``; the two
parse the same bytes into the same probabilities.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

#: Environment variable naming the declaration file, mirroring the other
#: oracle layers (``AT_PHYSICS``, ``AT_PREQUENTIAL`` ...).
REPLICATION_ENV = 'AT_REPLICATION'

#: The probability for a capability the declaration does not name. Small on
#: purpose: unnamed capabilities are the routine ones, and ``p * L > g`` makes
#: even a small ``p`` a deterrent when ``L`` is a tier demotion.
DEFAULT_PROB = 0.05


#: The most steps a replayable capability may declare: the bisection game's
#: bound (C ``AT_REPL_MAX_STEPS``).
MAX_STEPS = 256

#: The default bound on one revealed state, in UTF-8 bytes (RD_12.6 plan §0.1).
DEFAULT_MAX_STATE_BYTES = 4096

#: The largest ``max_state_bytes`` a declaration may ask for: a reveal carries
#: two states, and it has to fit a negotiation frame.
MAX_STATE_BYTES_LIMIT = 65536


@dataclass(frozen=True)
class ReplaySpec:
    """A capability the operator declares deterministically replayable
    (RD_12.6 plan §0.1, D1 and D2): its executor commits to a hash-chained
    trace of at most ``max_steps`` states, none over ``max_state_bytes``."""

    max_steps: int = MAX_STEPS
    max_state_bytes: int = DEFAULT_MAX_STATE_BYTES


class ReplicationDeclarationError(ValueError):
    """A replication declaration that does not parse or does not validate."""


@dataclass(frozen=True)
class ReplicationModel:
    """Parsed replication declaration: a default probability and per-capability
    overrides, both already validated into ``[0, 1]``."""

    default_prob: float = DEFAULT_PROB
    capabilities: dict[str, float] = field(default_factory=dict)
    #: Per-capability agreement tolerance for the adjudicator (R+D.md §12.6
    #: slice B). Two numeric results agree when they differ by at most this;
    #: the default 0.0 is exact equality, which is also how non-numeric
    #: results are always compared.
    tolerances: dict[str, float] = field(default_factory=dict)
    #: Capabilities declared replayable. Only these are replicated live
    #: (RD_12.6 plan §0.1, D12): a capability without a ``replay`` object is
    #: never sampled by a running node, whatever its probability.
    replays: dict[str, ReplaySpec] = field(default_factory=dict)

    def replay_for(self, capability: str) -> 'ReplaySpec | None':
        """The replay contract declared for ``capability``, or None."""
        return self.replays.get(capability)

    def live_prob_for(self, capability: str) -> float:
        """The probability a running node replicates ``capability`` with:
        :meth:`prob_for` for a replayable capability, 0.0 for any other."""
        return self.prob_for(capability) if capability in self.replays else 0.0

    def prob_for(self, capability: str) -> float:
        """The replication probability for ``capability``: its own declared
        number, or ``default_prob`` when the declaration does not name it."""
        return self.capabilities.get(capability, self.default_prob)

    def tolerance_for(self, capability: str) -> float:
        """The numeric agreement tolerance for ``capability``; 0.0 (exact)
        when the declaration does not name one."""
        return self.tolerances.get(capability, 0.0)


EMPTY_MODEL = ReplicationModel()


def _check_prob(value, where: str) -> float:
    try:
        p = float(value)
    except (TypeError, ValueError):
        raise ReplicationDeclarationError(f'{where}: not a number: {value!r}')
    if not (0.0 <= p <= 1.0):
        raise ReplicationDeclarationError(
            f'{where}: probability {p} out of [0, 1]')
    return p


def _check_bound(spec, key: str, default: int, low: int, high: int,
                 where: str) -> int:
    value = spec.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ReplicationDeclarationError(f'{where} {key}: not an integer: {value!r}')
    if not low <= value <= high:
        raise ReplicationDeclarationError(
            f'{where} {key}: {value} out of [{low}, {high}]')
    return value


def _parse_replay(spec, where: str) -> ReplaySpec:
    if not isinstance(spec, dict):
        raise ReplicationDeclarationError(f'{where} replay: not an object')
    return ReplaySpec(
        max_steps=_check_bound(spec, 'max_steps', MAX_STEPS, 1, MAX_STEPS,
                               f'{where} replay'),
        max_state_bytes=_check_bound(spec, 'max_state_bytes',
                                     DEFAULT_MAX_STATE_BYTES, 1,
                                     MAX_STATE_BYTES_LIMIT, f'{where} replay'))


def parse_replication(doc) -> ReplicationModel:
    """Validate a decoded replication declaration into a :class:`ReplicationModel`."""
    if not isinstance(doc, dict):
        raise ReplicationDeclarationError('declaration is not an object')
    version = doc.get('version')
    if version != 1:
        raise ReplicationDeclarationError(
            f'unsupported version {version!r}; expected 1')
    default_prob = _check_prob(doc.get('default_prob', DEFAULT_PROB),
                               'default_prob')
    caps_doc = doc.get('capabilities', {}) or {}
    if not isinstance(caps_doc, dict):
        raise ReplicationDeclarationError('capabilities is not an object')
    capabilities: dict[str, float] = {}
    tolerances: dict[str, float] = {}
    replays: dict[str, ReplaySpec] = {}
    for cap, spec in caps_doc.items():
        if not isinstance(spec, dict):
            raise ReplicationDeclarationError(
                f'capability {cap!r}: not an object')
        if 'replay' in spec:
            replays[cap] = _parse_replay(spec['replay'], f'capability {cap!r}')
        if 'replicate_prob' in spec:
            capabilities[cap] = _check_prob(spec['replicate_prob'],
                                            f'capability {cap!r} replicate_prob')
        elif cap not in replays:
            # A replayable capability may leave its probability to
            # default_prob; any other entry exists only to set one.
            raise ReplicationDeclarationError(
                f'capability {cap!r}: missing replicate_prob')
        if 'tolerance' in spec:
            tol = spec['tolerance']
            try:
                tol = float(tol)
            except (TypeError, ValueError):
                raise ReplicationDeclarationError(
                    f'capability {cap!r} tolerance: not a number: {tol!r}')
            if tol < 0.0:
                raise ReplicationDeclarationError(
                    f'capability {cap!r} tolerance: negative')
            tolerances[cap] = tol
    return ReplicationModel(default_prob=default_prob,
                            capabilities=capabilities, tolerances=tolerances,
                            replays=replays)


def load_replication(path: str) -> ReplicationModel:
    """Read and validate a replication declaration from ``path``."""
    with open(path, encoding='utf-8') as handle:
        return parse_replication(json.load(handle))


def load_replication_env() -> ReplicationModel:
    """Load the declaration named by ``AT_REPLICATION``, or the empty model
    (no capability sampled beyond ``default_prob``) when it is unset."""
    path = os.environ.get(REPLICATION_ENV)
    if not path:
        return EMPTY_MODEL
    return load_replication(path)
