# ******************
#  Copyright 2025 Sean M. Brennan and contributors
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
"""Behavioural adversary/benign archetypes for the resilience/threat M&S
red-team suite (SOW Task 3.4).

Each archetype is a *behavioural footprint*: a deterministic, seeded generator of
the per-peer ``AccessEvent`` stream the behaviour layer would observe. These are
NOT the network/identity-level attacks the docker-based ``evaluation/redteam``
exercises (Paxos Byzantine, container Sybil, iptables partition) — they are what
each threat *looks like in the access stream*, which is the only thing the
behaviour layer can see. Where a threat is primarily an identity/network concern
(Sybil cloning, true partition), we model its behavioural residue and let the
metrics report honestly what the behaviour layer does and does not catch.

The crucial benign-but-abnormal archetype is **DDIL** (disrupted/intermittent
comms): a *legitimate* peer whose timing/refusal features shift under a degraded
link though its capabilities and transaction quality stay normal. It is the
false-exclusion trap the SOW's base-rate analysis is about — the layer must not
exclude it. Ground-truth labels (`adversary`) drive the confusion matrix.
"""
from __future__ import annotations

import random
from dataclasses import dataclass
from typing import List, Optional, Tuple

from ..features import AccessEvent

# A fixed "normal" vocabulary the whole population draws from, so a peer that
# suddenly probes unknown capabilities / scatters counterparties stands out.
NORMAL_CAPS = ('telemetry.report', 'data.publish', 'status.ping', 'cmd.ack')
NORMAL_PEERS = ('peer-A', 'peer-B', 'peer-C', 'peer-D')

#: Archetype names (also the threat taxonomy rows of the M&S report).
BENIGN = 'benign'
COMPROMISED_CREDENTIAL = 'compromised_credential'  # the M5 exit target
BYZANTINE = 'byzantine'
SYBIL = 'sybil'
DDIL = 'ddil'                                       # benign-but-disrupted

ARCHETYPES = (BENIGN, COMPROMISED_CREDENTIAL, BYZANTINE, SYBIL, DDIL)
#: Which archetypes a correct detector SHOULD exclude (ground truth).
ADVERSARY_ARCHETYPES = frozenset({COMPROMISED_CREDENTIAL, BYZANTINE, SYBIL})


@dataclass(frozen=True)
class PeerProfile:
    """One simulated peer: its archetype, ground-truth label, and behaviour-
    change onset (the event index after which an adversary starts misbehaving,
    or a DDIL peer's link degrades). ``None`` onset = steady throughout."""
    peer_id: str
    role: str
    archetype: str
    adversary: bool
    onset_index: Optional[int]


def _normal_event(rng: random.Random, t: float) -> Tuple[AccessEvent, float]:
    """Realistic, varied normal traffic (spread, so the learned envelope is wide
    and a lone perturbation does not trip it)."""
    ev = AccessEvent(time=t, capability=rng.choice(NORMAL_CAPS),
                     refused=(rng.random() < 0.05),
                     score=min(1.0, max(0.0, rng.gauss(0.85, 0.05))),
                     counterparty=rng.choice(NORMAL_PEERS))
    return ev, max(0.1, rng.gauss(1.0, 0.2))


def _abusive_event(rng: random.Random, t: float) -> Tuple[AccessEvent, float]:
    """Compromised-but-credentialed abuse: capability probing, ~50% refusals,
    poor transaction scores, scattered counterparties, bursty cadence -- many
    features sustained off-envelope at once."""
    ev = AccessEvent(time=t, capability=f'probe-{rng.randrange(12)}',
                     refused=(rng.random() < 0.5),
                     score=min(1.0, max(0.0, rng.gauss(0.15, 0.05))),
                     counterparty=f'cp-{rng.randrange(12)}')
    return ev, rng.choice((0.05, 0.1, 2.0, 3.0))


def _byzantine_event(rng: random.Random, t: float) -> Tuple[AccessEvent, float]:
    """Inconsistent/contradictory behaviour: oscillating scores and a mix of
    normal and probing capabilities -- high variance rather than uniformly bad."""
    if rng.random() < 0.5:
        ev = AccessEvent(time=t, capability=rng.choice(NORMAL_CAPS),
                         refused=False,
                         score=min(1.0, max(0.0, rng.gauss(0.9, 0.05))),
                         counterparty=rng.choice(NORMAL_PEERS))
    else:
        ev = AccessEvent(time=t, capability=f'probe-{rng.randrange(12)}',
                         refused=(rng.random() < 0.7),
                         score=min(1.0, max(0.0, rng.gauss(0.1, 0.05))),
                         counterparty=f'cp-{rng.randrange(12)}')
    return ev, rng.choice((0.05, 0.2, 1.0, 2.5))


def _sybil_event(rng: random.Random, t: float) -> Tuple[AccessEvent, float]:
    """A thin, templated identity: one or two capabilities, a single
    counterparty, metronomic cadence -- *too regular* (near-zero diversity and
    jitter), the behavioural residue of a cloned/scripted node."""
    ev = AccessEvent(time=t, capability='telemetry.report', refused=False,
                     score=min(1.0, max(0.0, rng.gauss(0.8, 0.01))),
                     counterparty='peer-A')
    return ev, 1.0  # perfectly periodic


def _ddil_event(rng: random.Random, t: float) -> Tuple[AccessEvent, float]:
    """Benign-but-disrupted: normal capabilities and good transaction scores,
    but a degraded link -> bursty timing and elevated refusals/timeouts. The
    false-exclusion trap: behaviour *looks* off without any malice."""
    ev = AccessEvent(time=t, capability=rng.choice(NORMAL_CAPS),
                     refused=(rng.random() < 0.35),   # link timeouts, not policy
                     score=min(1.0, max(0.0, rng.gauss(0.82, 0.06))),
                     counterparty=rng.choice(NORMAL_PEERS))
    # bursty: clumps of near-zero gaps separated by long stalls
    dt = rng.choice((0.02, 0.05, 0.05, 8.0, 12.0))
    return ev, dt


_GEN = {
    BENIGN: _normal_event,
    COMPROMISED_CREDENTIAL: _abusive_event,
    BYZANTINE: _byzantine_event,
    SYBIL: _sybil_event,
    DDIL: _ddil_event,
}


def generate_stream(profile: PeerProfile, rng: random.Random,
                    n_events: int) -> List[AccessEvent]:
    """Produce ``profile``'s full ``AccessEvent`` stream. Before ``onset_index``
    the peer behaves normally (warmup + cover); at/after onset it switches to its
    archetype's footprint. A steady archetype (onset ``None``) uses its footprint
    throughout, except SYBIL which is its footprint from the start (no cover)."""
    onset = profile.onset_index if profile.onset_index is not None else 0
    post_gen = _GEN[profile.archetype]
    events: List[AccessEvent] = []
    t = 0.0
    for i in range(n_events):
        if i < onset and profile.archetype != SYBIL:
            ev, dt = _normal_event(rng, t)   # credentialed cover before onset
        else:
            ev, dt = post_gen(rng, t)
        events.append(ev)
        t += dt
    return events


def onset_time(profile: PeerProfile, stream: List[AccessEvent]) -> Optional[float]:
    """The wall-clock ``time`` at which ``profile``'s behaviour change begins
    (for detection-latency). ``None`` for a steady benign peer."""
    if profile.archetype == BENIGN:
        return None
    idx = profile.onset_index or 0
    if idx >= len(stream):
        return None
    return stream[idx].time
