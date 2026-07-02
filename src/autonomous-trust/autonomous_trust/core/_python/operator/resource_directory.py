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
"""Operator resource directory read-model (PIV_MFA_OPERATOR_ACCESS_PLAN.md §3.5).

Turns the raw ``peer_capabilities`` map into an operator-usable directory: for
each resource (capability), which peers provide it, each provider's standing,
and whether *this* operator can currently invoke it (``my_reach``).

Key design point (matches the trust model): tier gating is **execution-time
only** -- a low-tier peer still *sees* high-tier capabilities. So the directory
lists everything and marks un-invokable resources **locked** rather than hiding
them (visibility != access).

This module is a pure read-model: `build_directory` maps plain inputs to a
snapshot, so it is deterministic and unit-testable. `OperatorProcess` (P3c)
adapts live `PeerCapabilities`/`Peers`/reputation/tier into these inputs and
emits snapshots to the TUI feedback queue.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Mapping, Optional


class Reach(Enum):
    """Whether the operator's current tier can invoke a resource."""
    INVOKABLE = 'invokable'            # my_tier >= required_tier
    LOCKED_BY_TIER = 'locked_by_tier'  # my_tier < required_tier (earn standing)
    UNKNOWN = 'unknown'                # required_tier not known yet


class ResourceKind(Enum):
    """Operator-legible category for a capability (PIV_..._PLAN.md §3.5)."""
    COMPUTE = 'compute'
    DATA_STREAM = 'data_stream'
    SERVICE = 'service'
    UNKNOWN = 'unknown'


@dataclass
class PeerInfo:
    """Standing of a peer that provides a resource."""
    peer: str
    name: str = ''
    tier: int = 0
    reputation: Optional[float] = None
    online: bool = True


@dataclass
class CapabilityDescriptor:
    """What is known about a capability (locally and/or from the wire)."""
    name: str
    kind: str = ResourceKind.UNKNOWN.value
    description: str = ''
    required_tier: Optional[int] = None     # None => unknown
    arg_schema: Optional[dict] = None       # {arg_name: type} or None


@dataclass
class Provider:
    """A peer offering a resource, in the directory output."""
    peer: str
    name: str = ''
    tier: int = 0
    reputation: Optional[float] = None
    online: bool = True


@dataclass
class Resource:
    name: str
    kind: str
    description: str
    required_tier: Optional[int]
    arg_schema: Optional[dict]
    providers: List[Provider] = field(default_factory=list)
    my_reach: Reach = Reach.UNKNOWN

    @property
    def online_provider_count(self) -> int:
        return sum(1 for p in self.providers if p.online)


@dataclass
class ResourceDirectory:
    resources: List[Resource] = field(default_factory=list)
    my_tier: int = 0

    def by_name(self, name: str) -> Optional[Resource]:
        for r in self.resources:
            if r.name == name:
                return r
        return None

    def invokable(self) -> List[Resource]:
        return [r for r in self.resources if r.my_reach is Reach.INVOKABLE]


def reach_for(required_tier: Optional[int], my_tier: int) -> Reach:
    """Compute reach: visible-but-locked when below the required tier."""
    if required_tier is None:
        return Reach.UNKNOWN
    return Reach.INVOKABLE if my_tier >= required_tier else Reach.LOCKED_BY_TIER


def build_directory(
        descriptors: Mapping[str, CapabilityDescriptor],
        providers: Mapping[str, List[str]],
        peers: Mapping[str, PeerInfo],
        my_tier: int = 0) -> ResourceDirectory:
    """Build a directory snapshot.

    Args:
        descriptors: cap_name -> what's known about the capability.
        providers:   cap_name -> peer_ids offering it (from PeerCapabilities).
        peers:       peer_id -> PeerInfo standing.
        my_tier:     the operator's own current trust tier.

    A capability appears if it has either a descriptor or a provider, so a
    resource with providers but no descriptor still lists (name + reach unknown),
    and a locally-known resource with no online providers still shows (so the
    operator sees it exists but has no one to serve it).
    """
    names = set(descriptors) | set(providers)
    resources: List[Resource] = []
    for name in sorted(names):
        desc = descriptors.get(name) or CapabilityDescriptor(name)
        prov_list: List[Provider] = []
        for pid in providers.get(name, []):
            info = peers.get(pid)
            if info is None:
                # Provider we have no standing record for -> show it offline/
                # unknown rather than dropping it.
                prov_list.append(Provider(peer=pid, online=False))
            else:
                prov_list.append(Provider(peer=info.peer, name=info.name,
                                          tier=info.tier,
                                          reputation=info.reputation,
                                          online=info.online))
        resources.append(Resource(
            name=name,
            kind=desc.kind or ResourceKind.UNKNOWN.value,
            description=desc.description,
            required_tier=desc.required_tier,
            arg_schema=desc.arg_schema,
            providers=prov_list,
            my_reach=reach_for(desc.required_tier, my_tier)))
    return ResourceDirectory(resources=resources, my_tier=my_tier)
