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
"""The join-policy declaration: how a joiner treats the cohort it joins
(R+D.md §14.4, RD_14.4_HOSTILE_JOIN_PLAN.md).

Schema (version 1)::

    {
      "version": 1,
      "enabled": true,
      "anchors": ["verified_contact", "zta", "operator"],
      "told_tier": 1,
      "own_evidence_min": 3,
      "burst_k": 3,
      "burst_interval_sec": 5,
      "burst_budget_factor": 4,
      "anchored_cohort_min": 1
    }

**Opt-in** (the user's call, D9): named by ``$AT_JOIN_POLICY``, absent is
inert, and every path that reads it behaves as before. A declaration that does
not parse or validate stops the node at start, rather than leaving the defense
silently off.

**The declaration chooses the anchors** (the user's call, D6): which
out-of-band evidence makes an identity one the joiner trusts before the cohort
tells it anything. ``anchors`` names classes from :data:`ANCHOR_CLASSES`; an
extension answers for each (first contact for contacts and siblings, ZTA for
credentials and the operator key), and a class no extension answers anchors
nobody. ``operator`` means the operator key of THIS node: its operator's
other nodes.

``told_tier`` and ``own_evidence_min`` bound what the cohort's word alone can
do (Phase 4): a peer this node holds no own evidence about reads at most
``told_tier`` (default 1, ``UNVERIFIED_RESTORE_TIER``) until it has at least
``own_evidence_min`` entries of this node's own (default 3), when its brought
score takes over. An anchored peer is not bounded.

``burst_k``, ``burst_interval_sec`` and ``burst_budget_factor`` shape the join
burst (Phase 5, D5 (b)): the bootstrap worker probes each bounded peer until it
holds ``burst_k`` probe verdicts (default ``own_evidence_min``, so the burst
just reaches graduation), one probe per ``burst_interval_sec`` (default 5),
spending at most ``burst_budget_factor``·N·k probes over N targets (default 4).

``anchored_cohort_min`` is how many of the cohort's members a joiner must
count as anchors before it forms an anchored cohort with them (Phase 6, D8
(b), default 1): a second group of its own, beside the cohort, holding the
reputation evidence among its members.

Unknown keys are refused, ``note`` aside: a misspelled key would otherwise
turn part of a security declaration off without a word. The C twin is
``src/c/autonomous_trust/identity/join_policy.c``; the two parse the same
bytes into the same policy.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

#: Environment variable naming the declaration file.
JOIN_POLICY_ENV = 'AT_JOIN_POLICY'

#: A first-contact contact whose safety number was compared, or a device its
#: operator key vouched for.
ANCHOR_VERIFIED_CONTACT = 'verified_contact'
#: A first-contact contact not (yet) verified: possession of a ticket only,
#: which a forwarded invitation link is enough for.
ANCHOR_UNVERIFIED_CONTACT = 'unverified_contact'
#: A ZTA credential that chains to one of our trust anchors and is bound to
#: the identity presenting it.
ANCHOR_ZTA = 'zta'
#: A node under this node's own operator key: a verified operator-key binding
#: (ZTA) or a sibling device (first contact).
ANCHOR_OPERATOR = 'operator'

ANCHOR_CLASSES = (ANCHOR_VERIFIED_CONTACT, ANCHOR_UNVERIFIED_CONTACT,
                  ANCHOR_ZTA, ANCHOR_OPERATOR)

#: The extensions that can answer each class; a declaration naming a class
#: none of them provides is refused at start.
ANCHOR_PROVIDERS = {
    ANCHOR_VERIFIED_CONTACT: ('first_contact',),
    ANCHOR_UNVERIFIED_CONTACT: ('first_contact',),
    ANCHOR_ZTA: ('zta',),
    ANCHOR_OPERATOR: ('zta', 'first_contact'),
}

_KEYS = frozenset({'version', 'enabled', 'anchors', 'told_tier',
                   'own_evidence_min', 'burst_k', 'burst_interval_sec',
                   'burst_budget_factor', 'anchored_cohort_min', 'note'})

#: Defaults for the Phase 4 bounds (the user's calls, 2026-10-26).
TOLD_TIER_DEFAULT = 1
OWN_EVIDENCE_MIN_DEFAULT = 3
#: Defaults for the Phase 5 join burst (the user's calls, 2026-10-27). burst_k
#: has none of its own: absent, it is own_evidence_min.
BURST_INTERVAL_SEC_DEFAULT = 5.0
BURST_BUDGET_FACTOR_DEFAULT = 4
#: Default for the Phase 6 anchored cohort (the user's call, 2026-10-27).
ANCHORED_COHORT_MIN_DEFAULT = 1
#: The highest trust tier (repprocess TIER_FLOORS).
_TIER_MAX = 4


class JoinPolicyError(ValueError):
    """A join-policy declaration that does not parse or does not validate."""


@dataclass(frozen=True)
class JoinPolicy:
    """Parsed join policy. The default is inert: nothing enabled, no anchor."""

    enabled: bool = False
    anchors: frozenset = field(default_factory=frozenset)
    told_tier: int = TOLD_TIER_DEFAULT
    own_evidence_min: int = OWN_EVIDENCE_MIN_DEFAULT
    burst_k: int = OWN_EVIDENCE_MIN_DEFAULT
    burst_interval_sec: float = BURST_INTERVAL_SEC_DEFAULT
    burst_budget_factor: int = BURST_BUDGET_FACTOR_DEFAULT
    anchored_cohort_min: int = ANCHORED_COHORT_MIN_DEFAULT


INERT = JoinPolicy()


def parse_join_policy(doc) -> JoinPolicy:
    """Validate a decoded join-policy declaration into a :class:`JoinPolicy`."""
    if not isinstance(doc, dict):
        raise JoinPolicyError('declaration is not an object')
    unknown = sorted(set(doc) - _KEYS)
    if unknown:
        raise JoinPolicyError('unknown key(s) %s' % ', '.join(unknown))
    version = doc.get('version')
    if isinstance(version, bool) or not isinstance(version, int) or version != 1:
        raise JoinPolicyError(f'unsupported version {version!r}; expected 1')
    enabled = doc.get('enabled', False)
    if not isinstance(enabled, bool):
        raise JoinPolicyError(f'enabled: not a boolean: {enabled!r}')
    anchors_doc = doc.get('anchors', [])
    if not isinstance(anchors_doc, list):
        raise JoinPolicyError('anchors is not a list')
    anchors = []
    for name in anchors_doc:
        if name not in ANCHOR_CLASSES:
            raise JoinPolicyError(f'anchors: unknown class {name!r}; '
                                  f'expected one of {", ".join(ANCHOR_CLASSES)}')
        if name in anchors:
            raise JoinPolicyError(f'anchors: {name!r} listed twice')
        anchors.append(name)
    told_tier = _bounded_int(doc, 'told_tier', TOLD_TIER_DEFAULT, 0, _TIER_MAX)
    own_min = _bounded_int(doc, 'own_evidence_min', OWN_EVIDENCE_MIN_DEFAULT,
                           1, None)
    burst_k = _bounded_int(doc, 'burst_k', own_min, 1, None)
    interval = doc.get('burst_interval_sec', BURST_INTERVAL_SEC_DEFAULT)
    if isinstance(interval, bool) or not isinstance(interval, (int, float)) \
            or not interval > 0 or interval == float('inf'):
        raise JoinPolicyError(f'burst_interval_sec: not a positive number: '
                              f'{interval!r}')
    factor = _bounded_int(doc, 'burst_budget_factor',
                          BURST_BUDGET_FACTOR_DEFAULT, 1, None)
    cohort_min = _bounded_int(doc, 'anchored_cohort_min',
                              ANCHORED_COHORT_MIN_DEFAULT, 1, None)
    return JoinPolicy(enabled=enabled, anchors=frozenset(anchors),
                      told_tier=told_tier, own_evidence_min=own_min,
                      burst_k=burst_k, burst_interval_sec=float(interval),
                      burst_budget_factor=factor,
                      anchored_cohort_min=cohort_min)


def _bounded_int(doc, key, default, low, high):
    """``doc[key]`` as an integer in [low, high] (no upper bound when high is
    None), or ``default`` when absent."""
    value = doc.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int):
        raise JoinPolicyError(f'{key}: not an integer: {value!r}')
    if value < low or (high is not None and value > high):
        raise JoinPolicyError(f'{key}: {value} out of range')
    return value


class AnchoredSet(object):
    """IPC carrier for the peers the join policy counts as anchors, from
    identity (which judges anchors: the hooks need its ZTA verifiers and
    contacts) to reputation (which leaves an anchored peer's told score
    unbounded, Phase 4). The user's call, 2026-10-26: a local carrier, as
    ``ChildGroupSet`` and ``PeerStanding`` are. Plain picklable object; it only
    travels the local queues, never the network. Handled in
    ``Protocol.run_message_handlers`` by setting ``Protocol.anchored``."""

    def __init__(self, uuids=()):
        self.uuids = frozenset(str(u) for u in uuids)

    def __eq__(self, other):
        return isinstance(other, AnchoredSet) and self.uuids == other.uuids

    def __hash__(self):
        return hash(self.uuids)

    def __repr__(self):
        return 'AnchoredSet(%d)' % len(self.uuids)


class ProbeCounts(object):
    """IPC carrier for the join burst (Phase 5, D5 (b)), from reputation to
    the bootstrap worker: each peer reputation reads under the told ceiling
    (not anchored, not slashed, short of ``own_evidence_min`` own entries) and
    how many probe verdicts this node holds about it. A peer absent from the
    map has left the set. The user's call, 2026-10-27: reputation reports the
    counts, so the burst and the ceiling read one source. Plain picklable
    object; it only travels the local queues, never the network. The C twin
    is PEER_PROBE_COUNT, one message per changed peer."""

    def __init__(self, counts=None):
        self.counts = {str(k): int(v) for k, v in (counts or {}).items()}

    def __eq__(self, other):
        return isinstance(other, ProbeCounts) and self.counts == other.counts

    def __hash__(self):
        return hash(frozenset(self.counts.items()))

    def __repr__(self):
        return 'ProbeCounts(%d)' % len(self.counts)


class AnchoredCohort(object):
    """IPC carrier for the anchored cohort this node holds (None: none), from
    identity to the sibling processes; reputation routes and scores by it.
    Plain picklable object; it only travels the local queues. Handled in
    ``Protocol.run_message_handlers`` by setting ``Protocol.anchored_cohort``.
    The C twin is the local ANCHORED_COHORT message."""

    def __init__(self, group=None):
        self.group = group

    def __repr__(self):
        return 'AnchoredCohort(%s)' % (
            str(self.group.uuid)[:8] if self.group is not None else None)


def load_join_policy(path: str) -> JoinPolicy:
    """Read and validate a join-policy declaration from ``path``."""
    with open(path, encoding='utf-8') as handle:
        try:
            doc = json.load(handle)
        except ValueError as err:
            raise JoinPolicyError(f'not JSON: {err}') from err
    return parse_join_policy(doc)


def load_join_policy_env() -> JoinPolicy:
    """Load the declaration named by ``$AT_JOIN_POLICY``, or :data:`INERT`
    when it is unset."""
    path = os.environ.get(JOIN_POLICY_ENV)
    if not path:
        return INERT
    return load_join_policy(path)


def missing_providers(policy: JoinPolicy, extension_names) -> list:
    """The declared anchor classes no loaded extension can answer, sorted."""
    names = set(extension_names)
    return sorted(cls for cls in policy.anchors
                  if not names.intersection(ANCHOR_PROVIDERS[cls]))


def check_join_policy(extension_names, logger=None) -> JoinPolicy:
    """Load ``$AT_JOIN_POLICY`` for a starting node and refuse what it cannot
    honour: a declaration that does not validate, or one enabling an anchor
    class no installed extension (``extension_names``) answers. Logs an ERROR
    and raises RuntimeError; returns the policy otherwise. C checks what is
    linked (identity_ext_present), the same question."""
    try:
        policy = load_join_policy_env()
        missing = missing_providers(policy, extension_names) if policy.enabled else []
        if missing:
            raise JoinPolicyError(
                'anchor class(es) %s need an extension this node lacks (%s)' % (
                    ', '.join(missing),
                    '; '.join('%s: %s' % (c, ' or '.join(ANCHOR_PROVIDERS[c]))
                              for c in missing)))
    except (OSError, JoinPolicyError) as err:
        msg = '$%s=%s: %s' % (JOIN_POLICY_ENV, os.environ.get(JOIN_POLICY_ENV, ''), err)
        if logger is not None:
            logger.error('Refusing to start: %s', msg)
        raise RuntimeError(msg) from err
    return policy
