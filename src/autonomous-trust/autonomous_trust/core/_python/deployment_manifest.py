# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
#  Licensed under the Apache License, Version 2.0
# ******************
"""The deployment manifest: which nodes may be gateways (RD_13.4 §3.3).

A deployment names its cohorts, their members, and the gateways it allows
between each pair of cohorts, in one canonical JSON file that both runtimes
read. The C twin is ``src/c/autonomous_trust/config/deployment_manifest.c``,
and the conformance case ``network/deployment-manifest`` pins the rules below
on both.

At runtime the manifest only **bounds**. A gateway role (RD_13.4 §3.2) is
accepted only for a node the manifest lists, and the role still needs both
cohorts' quorum certificates, so the file grants nothing by itself. With no
manifest, no role is accepted, which leaves one gateway per pair of cohorts and
invariant G exactly as it was. Cohorts are named here for the offline checker
(``tools/robustness_check.py``) and for validation; the runtime bound is by node
alone (RD_13.4 R1), because group uuids are minted at runtime and a cohort that
re-forms gets a new one.

Schema, version 1::

    {
      "version": 1,
      "cohorts": {
        "<name>": {"members": ["<identity uuid>", ...], "n_min": 4}
      },
      "gateways": [
        {"node": "<identity uuid>", "between": ["<name>", "<name>"]}
      ]
    }

``n_min`` is optional and read only by the checker. Every other key is
refused, as is anything that would describe a topology invariant G forbids:

* a node in two cohorts that is not a gateway between exactly those two;
* a gateway that is not a member of both cohorts it bridges;
* the same node listed twice for the same pair, or a pair of one cohort.

Set ``AT_DEPLOYMENT_MANIFEST`` to the file's path. Unset, the manifest is
empty. Set to a file that does not exist, it is empty and a warning is logged,
because empty is the restrictive answer. A file that exists and breaks a rule
is an error and the node refuses to start: whoever wrote it meant to declare
gateways, and quietly running without them would hide the mistake.
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Union
from uuid import UUID

logger = logging.getLogger(__name__)

#: Env var naming the manifest file. Mirrors C DEPLOYMENT_MANIFEST_ENV.
DEPLOYMENT_MANIFEST_ENV = 'AT_DEPLOYMENT_MANIFEST'

#: The only schema version this loader reads.
MANIFEST_VERSION = 1

#: Ceilings, matching C. A manifest beyond them is a configuration error.
MAX_COHORTS = 64
MAX_MEMBERS = 1024          # per cohort
MAX_GATEWAYS = 256
MAX_NAME_LEN = 64
_NAME_RE = re.compile(r'[A-Za-z0-9._-]{1,%d}' % MAX_NAME_LEN)

PathLike = Union[str, 'os.PathLike[str]', Path]


class ManifestError(ValueError):
    """A manifest that exists and breaks a rule. The node refuses to start."""


@dataclass(frozen=True)
class Cohort:
    name: str
    members: tuple[str, ...]
    n_min: Optional[int] = None


@dataclass(frozen=True)
class GatewayEntry:
    node: str
    between: tuple[str, str]     # sorted, so a pair has one spelling


@dataclass(frozen=True)
class DeploymentManifest:
    cohorts: dict[str, Cohort] = field(default_factory=dict)
    gateways: tuple[GatewayEntry, ...] = ()

    def is_empty(self) -> bool:
        return not self.gateways and not self.cohorts

    def gateway_pairs(self, node) -> int:
        """How many cohort pairs *node* is listed as a gateway for. Zero means
        no role may be accepted for it (RD_13.4 R1: the runtime bound is by
        node)."""
        node = str(node)
        return sum(1 for g in self.gateways if g.node == node)

    def may_be_gateway(self, node) -> bool:
        return self.gateway_pairs(node) > 0


def empty_manifest() -> DeploymentManifest:
    return DeploymentManifest()


def _canonical_uuid(value, where: str) -> str:
    if not isinstance(value, str):
        raise ManifestError(f'{where}: not a uuid string: {value!r}')
    try:
        canon = str(UUID(value))
    except ValueError:
        raise ManifestError(f'{where}: not a uuid: {value!r}') from None
    if canon != value:
        raise ManifestError(
            f'{where}: {value!r} is not in canonical form (lowercase, hyphenated)')
    return canon


def _check_name(name, where: str) -> str:
    # ASCII only, so C's byte length and Python's character length agree.
    if not isinstance(name, str) or not _NAME_RE.fullmatch(name):
        raise ManifestError(
            f'{where}: cohort name must be 1 to {MAX_NAME_LEN} of '
            f'[A-Za-z0-9._-]: {name!r}')
    return name


def _no_duplicates(pairs):
    # jansson's JSON_REJECT_DUPLICATES, so a key listed twice is not read as
    # the last one on Python and refused on C.
    keys = [k for k, _ in pairs]
    if len(set(keys)) != len(keys):
        raise ManifestError('manifest: a key appears twice in one object')
    return dict(pairs)


def parse_manifest(data) -> DeploymentManifest:
    """Validate an already-decoded manifest. Raises ManifestError."""
    if not isinstance(data, dict):
        raise ManifestError('manifest: not a JSON object')
    extra = set(data) - {'version', 'cohorts', 'gateways'}
    if extra:
        raise ManifestError(f'manifest: unknown key(s) {sorted(extra)}')
    version = data.get('version')
    if type(version) is not int or version != MANIFEST_VERSION:
        raise ManifestError(
            f'manifest: version must be {MANIFEST_VERSION}, got {version!r}')

    raw_cohorts = data.get('cohorts', {})
    if not isinstance(raw_cohorts, dict):
        raise ManifestError('manifest: cohorts is not an object')
    if len(raw_cohorts) > MAX_COHORTS:
        raise ManifestError(f'manifest: more than {MAX_COHORTS} cohorts')
    cohorts: dict[str, Cohort] = {}
    for name, body in raw_cohorts.items():
        _check_name(name, 'cohorts')
        where = f'cohorts.{name}'
        if not isinstance(body, dict):
            raise ManifestError(f'{where}: not an object')
        extra = set(body) - {'members', 'n_min'}
        if extra:
            raise ManifestError(f'{where}: unknown key(s) {sorted(extra)}')
        members = body.get('members')
        if not isinstance(members, list) or not members:
            raise ManifestError(f'{where}.members: must be a non-empty list')
        if len(members) > MAX_MEMBERS:
            raise ManifestError(f'{where}.members: more than {MAX_MEMBERS}')
        canon = [_canonical_uuid(m, f'{where}.members') for m in members]
        if len(set(canon)) != len(canon):
            raise ManifestError(f'{where}.members: a member is listed twice')
        n_min = body.get('n_min')
        if n_min is not None and (type(n_min) is not int or n_min < 1):
            raise ManifestError(f'{where}.n_min: must be an integer of at least 1')
        cohorts[name] = Cohort(name, tuple(canon), n_min)

    raw_gateways = data.get('gateways', [])
    if not isinstance(raw_gateways, list):
        raise ManifestError('manifest: gateways is not a list')
    if len(raw_gateways) > MAX_GATEWAYS:
        raise ManifestError(f'manifest: more than {MAX_GATEWAYS} gateways')
    gateways: list[GatewayEntry] = []
    seen = set()
    for i, entry in enumerate(raw_gateways):
        where = f'gateways[{i}]'
        if not isinstance(entry, dict) or set(entry) != {'node', 'between'}:
            raise ManifestError(f'{where}: must be an object with exactly '
                                f'"node" and "between"')
        node = _canonical_uuid(entry['node'], f'{where}.node')
        between = entry['between']
        if not isinstance(between, list) or len(between) != 2:
            raise ManifestError(f'{where}.between: must name two cohorts')
        a, b = (_check_name(n, f'{where}.between') for n in between)
        if a == b:
            raise ManifestError(f'{where}.between: names one cohort twice')
        for n in (a, b):
            if n not in cohorts:
                raise ManifestError(f'{where}.between: no cohort named {n!r}')
            if node not in cohorts[n].members:
                raise ManifestError(
                    f'{where}: {node} is not a member of cohort {n!r}')
        pair = tuple(sorted((a, b)))
        if (node, pair) in seen:
            raise ManifestError(f'{where}: {node} is listed twice for {pair}')
        seen.add((node, pair))
        gateways.append(GatewayEntry(node, pair))

    # Invariant G, at design time: a node in two cohorts is a gateway between
    # them, and a node in three or more is a gateway between every pair.
    membership: dict[str, list[str]] = {}
    for c in cohorts.values():
        for m in c.members:
            membership.setdefault(m, []).append(c.name)
    for node, names in membership.items():
        if len(names) < 2:
            continue
        names = sorted(names)
        for i in range(len(names)):
            for j in range(i + 1, len(names)):
                if (node, (names[i], names[j])) not in seen:
                    raise ManifestError(
                        f'manifest: {node} is in cohorts {names[i]!r} and '
                        f'{names[j]!r} but is not a gateway between them '
                        f'(invariant G)')

    return DeploymentManifest(cohorts, tuple(gateways))


def load_manifest(path: Optional[PathLike] = None) -> DeploymentManifest:
    """Load the manifest at *path*, or the one ``AT_DEPLOYMENT_MANIFEST``
    names, or the empty manifest.

    An explicit path that does not exist raises FileNotFoundError, because the
    caller asked for that file. An env-named path that does not exist gives the
    empty manifest with a warning. A file that exists and breaks a rule raises
    ManifestError either way.
    """
    explicit = path is not None
    if path is None:
        env = os.environ.get(DEPLOYMENT_MANIFEST_ENV)
        if not env:
            return empty_manifest()
        path = env
    path = Path(path)
    if not path.exists():
        if explicit:
            raise FileNotFoundError(f'deployment manifest: {path} not found')
        logger.warning('deployment manifest: %s=%s not found; no gateway role '
                       'will be accepted', DEPLOYMENT_MANIFEST_ENV, path)
        return empty_manifest()
    try:
        data = json.loads(path.read_text(), object_pairs_hook=_no_duplicates)
    except (OSError, ValueError) as exc:
        raise ManifestError(f'deployment manifest: cannot read {path}: {exc}') \
            from exc
    try:
        return parse_manifest(data)
    except ManifestError as exc:
        raise ManifestError(f'{path}: {exc}') from None


# The manifest a running node holds, loaded once at network start. Mirrors C
# deployment_manifest_configure / _active / _reset.
_active: DeploymentManifest = empty_manifest()


def configure(path: Optional[PathLike] = None) -> DeploymentManifest:
    """Load the manifest and make it the active one. Raises ManifestError (the
    node then refuses to start) and leaves the previous one in force."""
    global _active
    _active = load_manifest(path)
    if _active.gateways:
        logger.info('deployment manifest: %d cohort(s), %d gateway entr%s',
                    len(_active.cohorts), len(_active.gateways),
                    'y' if len(_active.gateways) == 1 else 'ies')
    return _active


def active() -> DeploymentManifest:
    return _active


def reset() -> None:
    global _active
    _active = empty_manifest()
