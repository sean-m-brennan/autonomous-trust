"""Cohort layout for a hierarchical dod_mission deployment.

One command cohort (squad, jet, command and the rq86 gateways, under the
coordinator) over N field cohorts. Field cohort k lives on its own subnet,
172.30.k.0/24; its gateway rq86-k is on both that subnet and the command subnet.
The compose generator and the cohort seeder both read this layout, which is
what keeps their addresses in agreement."""
from __future__ import annotations

import os
from dataclasses import dataclass, field

COMMAND_NETWORK = "dod-net"
COMMAND_SUBNET_BASE = "172.30.0"
BASE_PEER_OCTET = 10
MAX_COHORT_ENV = "AT_COHORT_SIZE"

_COMMAND_PREFIXES = ("squad-", "jet-", "rq86-")
_COMMAND_NAMES = ("command",)


def field_network(k: int) -> str:
    return f"dod-field-{k}"


def field_subnet(k: int) -> str:
    return f"172.30.{k}.0/24"


def cohort_size_from_env() -> int | None:
    """The cohort cap from AT_COHORT_SIZE; None (unset, 0 or not a number)
    means a flat deployment."""
    raw = os.environ.get(MAX_COHORT_ENV, "").strip()
    return int(raw) if raw.isdigit() and int(raw) > 0 else None


@dataclass
class Cohort:
    index: int          # 1-based; also the field subnet's third octet
    gateway: str
    anchor: str         # Python microdrone seeded to welcome cold joiners
    members: list[str] = field(default_factory=list)   # gateway excluded


@dataclass
class Layout:
    command: list[str]
    cohorts: list[Cohort]
    addresses: dict[str, dict[str, str]]   # peer -> network name -> IPv4

    def cohort_of(self, peer: str) -> Cohort | None:
        for c in self.cohorts:
            if peer in c.members or peer == c.gateway:
                return c
        return None

    def ip(self, peer: str, network: str) -> str:
        return self.addresses[peer][network]

    def c_microdrones(self) -> list[str]:
        """Every field microdrone except the cohort anchors, which run Python."""
        anchors = {c.anchor for c in self.cohorts}
        return [p for c in self.cohorts for p in c.members
                if p.startswith("microdrone-") and p not in anchors]

    def field_peers(self, k: int) -> list[str]:
        return list(self.cohorts[k - 1].members)


def _is_command(name: str) -> bool:
    return name.startswith(_COMMAND_PREFIXES) or name in _COMMAND_NAMES


def _microdrone_key(name: str):
    return (0, int(name.rsplit("-", 1)[-1])) if name.startswith("microdrone-") else (1, name)


def plan_layout(scenario, max_cohort: int = 32) -> Layout:
    peers = list(scenario.peers)
    command = [p for p in peers if _is_command(p)]
    gateways = sorted((p for p in command if p.startswith("rq86-")),
                      key=lambda n: int(n.rsplit("-", 1)[-1]))
    field_names = sorted((p for p in peers if not _is_command(p)), key=_microdrone_key)
    n = len(gateways)
    if n == 0:
        raise ValueError("hierarchy needs at least one rq86 gateway")
    # Round-robin keeps cohorts within one of each other in size and spreads
    # the sensors; mq800 goes first so that it lands in cohort 1.
    if "mq800" in field_names:
        field_names.remove("mq800")
        field_names.insert(0, "mq800")
    buckets = [[] for _ in range(n)]
    for i, name in enumerate(field_names):
        buckets[i % n].append(name)
    cohorts = []
    for k, (gw, members) in enumerate(zip(gateways, buckets), start=1):
        if len(members) + 1 > max_cohort:
            raise ValueError(f"cohort {k} needs {len(members) + 1} nodes, over {max_cohort}")
        anchor = next((m for m in members if m.startswith("microdrone-")), None)
        if anchor is None:
            raise ValueError(f"cohort {k} has no microdrone to anchor it")
        cohorts.append(Cohort(index=k, gateway=gw, anchor=anchor, members=members))
    addresses: dict[str, dict[str, str]] = {}
    for i, name in enumerate(command):
        addresses.setdefault(name, {})[COMMAND_NETWORK] = \
            f"{COMMAND_SUBNET_BASE}.{BASE_PEER_OCTET + i}"
    for c in cohorts:
        net = field_network(c.index)
        addresses[c.gateway][net] = f"172.30.{c.index}.{BASE_PEER_OCTET}"
        for j, name in enumerate(c.members, start=1):
            addresses.setdefault(name, {})[net] = f"172.30.{c.index}.{BASE_PEER_OCTET + j}"
    return Layout(command=command, cohorts=cohorts, addresses=addresses)
