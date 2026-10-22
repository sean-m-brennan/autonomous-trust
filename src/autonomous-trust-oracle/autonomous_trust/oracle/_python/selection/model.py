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
"""The selection declaration: which capabilities a requestor assigns to k of
N peers, and with what exploration floor (RD_12.7 plan §3.3).

Schema (version 1)::

    {
      "version": 1,
      "default": {"k": null, "floor": 0.05},
      "probe": {"floor": 0.05},
      "capabilities": {
        "demo.command-issue": {"k": null},
        "demo.query": {"k": 1, "floor": 0.1}
      },
      "log_records": 4096
    }

``k: null`` fans out to every eligible peer, which is today's behavior and the
default for a capability the declaration does not name. A positive ``k``
selects; under Bernoulli inclusion it is the MEAN set size, not a fixed one
(§3.2). ``floor`` is the least selection probability any eligible peer has
(D4(b)), and 0 is legal: "this capability is never explored" is an operator's
choice the file records. ``probe`` present turns the prober's deterministic
UCB1 argmax into a draw over the UCB1 bonuses (§3.4); absent, the prober is
unchanged. ``log_records`` bounds the persisted decision log (§0.2).

**Absent means inert.** No ``AT_SELECTION``, no selection: every capability
fans out and the prober keeps its argmax, so the core path is byte-for-byte
the old one. A malformed declaration is fatal at load, as ``replication.json``
is, because a bad number in an authored file is a mistake to surface.

The C twin is ``src/c/extensions/selection/selection.c``; the two parse the
same bytes into the same policies.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Optional

#: Environment variable naming the declaration file.
SELECTION_ENV = 'AT_SELECTION'

#: The floor for a capability the declaration names without one.
DEFAULT_FLOOR = 0.05

#: The decision log's default bound, in records (RD_12.7 plan §0.2).
DEFAULT_LOG_RECORDS = 4096

#: The largest bound a declaration may ask for.
MAX_LOG_RECORDS = 1 << 20

#: The largest k a declaration may ask for. A k at or above the eligible
#: count selects everyone, so this only bounds a typo.
MAX_K = 1024

#: The most capabilities a declaration may name (C AT_SEL_MAX_CAPS).
MAX_CAPS = 64


class SelectionDeclarationError(ValueError):
    """A selection declaration that does not parse or does not validate."""


@dataclass(frozen=True)
class Policy:
    """How one capability is assigned: ``k`` None fans out to everyone."""

    k: Optional[int] = None
    floor: float = DEFAULT_FLOOR


@dataclass(frozen=True)
class SelectionModel:
    """A parsed selection declaration. ``declared`` is False only for the
    empty model, which selects nothing and leaves the prober alone."""

    declared: bool = False
    default: Policy = Policy()
    probe_floor: Optional[float] = None
    capabilities: dict[str, Policy] = field(default_factory=dict)
    log_records: int = DEFAULT_LOG_RECORDS

    def policy_for(self, capability: str) -> Policy:
        """The capability's own policy, or the declaration's default."""
        return self.capabilities.get(capability, self.default)

    def selects(self, capability: str) -> bool:
        """True when ``capability`` is drawn from rather than fanned out."""
        return self.declared and self.policy_for(capability).k is not None


EMPTY_MODEL = SelectionModel()


def _check_floor(value, where: str) -> float:
    # A JSON number only: no boolean, and no string Python's float() would
    # read but C's parser refuses.
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise SelectionDeclarationError(f'{where}: not a number: {value!r}')
    floor = float(value)
    if not 0.0 <= floor <= 1.0:
        raise SelectionDeclarationError(f'{where}: {floor} out of [0, 1]')
    return floor


def _check_k(value, where: str) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise SelectionDeclarationError(f'{where}: not an integer or null: {value!r}')
    if not 1 <= value <= MAX_K:
        raise SelectionDeclarationError(f'{where}: {value} out of [1, {MAX_K}]')
    return value


def _parse_policy(spec, where: str, base: Policy) -> Policy:
    if not isinstance(spec, dict):
        raise SelectionDeclarationError(f'{where}: not an object')
    unknown = set(spec) - {'k', 'floor', 'note'}
    if unknown:
        raise SelectionDeclarationError(f'{where}: unknown key(s) {sorted(unknown)}')
    k = _check_k(spec['k'], f'{where} k') if 'k' in spec else base.k
    floor = (_check_floor(spec['floor'], f'{where} floor') if 'floor' in spec
             else base.floor)
    return Policy(k=k, floor=floor)


def parse_selection(doc) -> SelectionModel:
    """Validate a decoded selection declaration into a :class:`SelectionModel`."""
    if not isinstance(doc, dict):
        raise SelectionDeclarationError('declaration is not an object')
    version = doc.get('version')
    if isinstance(version, bool) or not isinstance(version, int) or version != 1:
        raise SelectionDeclarationError(
            f'unsupported version {doc.get("version")!r}; expected 1')
    unknown = set(doc) - {'version', 'default', 'probe', 'capabilities',
                          'log_records', 'note'}
    if unknown:
        raise SelectionDeclarationError(f'unknown key(s) {sorted(unknown)}')
    default = _parse_policy(doc.get('default', {}), 'default', Policy())
    probe_floor = None
    if 'probe' in doc:
        probe = doc['probe']
        if not isinstance(probe, dict):
            raise SelectionDeclarationError('probe: not an object')
        if set(probe) - {'floor', 'note'}:
            raise SelectionDeclarationError(
                f'probe: unknown key(s) {sorted(set(probe) - {"floor", "note"})}')
        probe_floor = _check_floor(probe.get('floor', DEFAULT_FLOOR), 'probe floor')
    caps_doc = doc.get('capabilities', {})
    if not isinstance(caps_doc, dict):
        raise SelectionDeclarationError('capabilities is not an object')
    if len(caps_doc) > MAX_CAPS:
        raise SelectionDeclarationError(
            f'capabilities: {len(caps_doc)} named, at most {MAX_CAPS}')
    capabilities = {cap: _parse_policy(spec, f'capability {cap!r}', default)
                    for cap, spec in caps_doc.items()}
    records = doc.get('log_records', DEFAULT_LOG_RECORDS)
    if isinstance(records, bool) or not isinstance(records, int) \
            or not 1 <= records <= MAX_LOG_RECORDS:
        raise SelectionDeclarationError(
            f'log_records: {records!r} not an integer in [1, {MAX_LOG_RECORDS}]')
    return SelectionModel(declared=True, default=default,
                          probe_floor=probe_floor, capabilities=capabilities,
                          log_records=records)


def load_selection(path: str) -> SelectionModel:
    """Read and validate a selection declaration from ``path``."""
    with open(path, encoding='utf-8') as handle:
        return parse_selection(json.load(handle))


def load_selection_env() -> SelectionModel:
    """The declaration named by ``AT_SELECTION``, or the empty model."""
    path = os.environ.get(SELECTION_ENV)
    if not path:
        return EMPTY_MODEL
    return load_selection(path)
