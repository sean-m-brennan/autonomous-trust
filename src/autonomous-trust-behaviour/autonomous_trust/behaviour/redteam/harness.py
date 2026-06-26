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
"""Deterministic resilience/threat M&S harness for the behavioural-anomaly layer
(SOW Task 3.4). Drives the *pure* library (`BehaviorMonitor`) and a static-policy
baseline over a synthetic peer population spanning the threat archetypes, then
reports detection latency, exclusion correctness, and the false-exclusion rate
projected to a realistic base rate (Axelsson) -- ML layer vs static baseline.

This is library-level M&S: no node, no network, no docker (the docker-based
`evaluation/redteam` is the separate live-mesh integration). Everything is seeded,
so a fixed config reproduces byte-identical metrics -- the determinism the SOW
exit criteria require, and the same property that makes a score admissible
evidence. The population is sampled with enough adversaries/benigns for
statistical power; the *operational* rarity of attackers enters only through the
base-rate projection, which is the methodologically correct way to state
precision (you measure class-conditional rates, then project to the real prior).
"""
from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .archetypes import (BENIGN, BYZANTINE, COMPROMISED_CREDENTIAL, DDIL, SYBIL,
                         ADVERSARY_ARCHETYPES, PeerProfile, generate_stream,
                         onset_time)
from .baseline import StaticPolicyDetector
from .metrics import DetectorMetrics, compute_metrics, make_outcome
from ..ensemble import BehaviorMonitor

#: Detector tuning for the M&S run. A larger HBOS window than the unit-test
#: config (closer to the prototype's real default) is deliberate: too small a
#: window lets the detector *adapt to* a slow sustained compromise and miss it
#: (a real finding -- detection races adaptation), so the window must be wide
#: enough that a sustained credentialed compromise is reliably caught.
DEFAULT_DETECTOR_KW = dict(
    hst_window=60, hst_trees=15, hst_height=10,
    hbos_window=200, hbos_refit_every=20, hbos_warmup=70,
    calib_warmup=30, min_obs=90, feature_window=48,
    enter=0.9, dwell_target=8, leak=2, calib_min_std=0.10)

ROLE = 'peer'


@dataclass
class RedTeamConfig:
    """Population composition + run parameters. Counts are chosen for
    statistical power, NOT to encode the operational attack base rate (that is
    applied analytically via ``ppv_at_base_rate``)."""
    n_benign: int = 30
    n_ddil: int = 8            # benign-but-disrupted -- the false-exclusion trap
    n_compromised: int = 8     # the M5 exit target
    n_byzantine: int = 5
    n_sybil: int = 5
    n_events: int = 420
    onset_index: int = 260     # behaviour change after warmup
    seed: int = 1234
    detector_kw: dict = field(default_factory=lambda: dict(DEFAULT_DETECTOR_KW))
    baseline_kw: dict = field(default_factory=dict)


@dataclass(frozen=True)
class RedTeamResult:
    config: RedTeamConfig
    ml: DetectorMetrics
    baseline: DetectorMetrics
    population: int

    def as_report(self) -> dict:
        return {
            'suite': 'behaviour-anomaly resilience/threat M&S (SOW Task 3.4)',
            'population': self.population,
            'seed': self.config.seed,
            'note': ('class-conditional rates measured on a powered sample; '
                     'precision projected to realistic base rates (Axelsson). '
                     'Sybil/DDIL probe the layer limits -- Sybil is primarily an '
                     'identity-layer concern, DDIL is a benign disruption that '
                     'must NOT be excluded.'),
            'ml_governed_sensor': self.ml.as_dict(),
            'static_baseline': self.baseline.as_dict(),
        }

    def to_markdown(self) -> str:
        m, b = self.ml, self.baseline
        def row(name, ml_v, bl_v):
            return f'| {name} | {ml_v} | {bl_v} |'
        lines = [
            '# Behavioural-Anomaly Resilience / Threat M&S (SOW Task 3.4)',
            '',
            f'Population: {self.population} peers · seed {self.config.seed} '
            '(deterministic).',
            '',
            '| Metric | ML governed sensor | Static baseline |',
            '|---|---|---|',
            row('Detection rate (TPR)', f'{m.tpr:.2f}', f'{b.tpr:.2f}'),
            row('False-exclusion rate (FPR)', f'{m.fpr:.2f}', f'{b.fpr:.2f}'),
            row('Precision @ observed mix', f'{m.ppv:.2f}', f'{b.ppv:.2f}'),
            row('Precision @ base-rate 0.05',
                f'{m.ppv_at_base_rate(0.05):.2f}',
                f'{b.ppv_at_base_rate(0.05):.2f}'),
            row('Precision @ base-rate 0.01',
                f'{m.ppv_at_base_rate(0.01):.2f}',
                f'{b.ppv_at_base_rate(0.01):.2f}'),
            row('Detection latency (mean)',
                f'{m.latency_mean:.1f}' if m.latency_mean is not None else '—',
                f'{b.latency_mean:.1f}' if b.latency_mean is not None else '—'),
            '',
            '## Per-archetype detection rate',
            '',
            '| Archetype | ML | baseline |',
            '|---|---|---|',
        ]
        for a in (COMPROMISED_CREDENTIAL, BYZANTINE, SYBIL, DDIL, BENIGN):
            mr = m.archetype_detection_rate(a)
            br = b.archetype_detection_rate(a)
            lines.append(row(
                a,
                f'{mr:.2f}' if mr is not None else '—',
                f'{br:.2f}' if br is not None else '—'))
        lines += [
            '',
            '_DDIL and benign rows are false-exclusion exposure (lower is '
            'better); Sybil is primarily caught by the identity layer._',
        ]
        return '\n'.join(lines)


def build_population(config: RedTeamConfig) -> List[PeerProfile]:
    profiles: List[PeerProfile] = []

    def add(n, archetype, adversary, onset):
        for i in range(n):
            pid = f'{archetype}-{i:02d}'
            profiles.append(PeerProfile(peer_id=pid, role=ROLE,
                                        archetype=archetype, adversary=adversary,
                                        onset_index=onset))
    add(config.n_benign, BENIGN, False, None)
    add(config.n_ddil, DDIL, False, config.onset_index)
    add(config.n_compromised, COMPROMISED_CREDENTIAL, True, config.onset_index)
    add(config.n_byzantine, BYZANTINE, True, config.onset_index)
    add(config.n_sybil, SYBIL, True, 0)   # templated identity from the start
    return profiles


def _peer_seed(master: int, peer_id: str) -> int:
    h = hashlib.blake2b(f'{master}:{peer_id}'.encode(), digest_size=4).digest()
    return int.from_bytes(h, 'big')


def run(config: Optional[RedTeamConfig] = None) -> RedTeamResult:
    """Run the suite and return the ML-vs-baseline result. Deterministic in
    ``config.seed``."""
    config = config or RedTeamConfig()
    profiles = build_population(config)

    monitor = BehaviorMonitor(base_seed=config.seed, **config.detector_kw)
    baseline = StaticPolicyDetector(**config.baseline_kw)

    ml_outcomes = []
    bl_outcomes = []
    for profile in profiles:
        rng = random.Random(_peer_seed(config.seed, profile.peer_id))
        stream = generate_stream(profile, rng, config.n_events)
        onset = onset_time(profile, stream)

        ml_flag_time: Optional[float] = None
        bl_flag_time: Optional[float] = None
        for ev in stream:
            monitor.observe(profile.peer_id, profile.role, ev)
            if ml_flag_time is None:
                for prop in monitor.poll_proposals():
                    if prop.peer_id == profile.peer_id:
                        ml_flag_time = ev.time
                        break
            if baseline.observe(profile.peer_id, ev) and bl_flag_time is None:
                bl_flag_time = ev.time

        ml_outcomes.append(make_outcome(
            profile, ml_flag_time is not None, onset, ml_flag_time))
        bl_outcomes.append(make_outcome(
            profile, bl_flag_time is not None, onset, bl_flag_time))

    return RedTeamResult(config=config,
                         ml=compute_metrics(ml_outcomes),
                         baseline=compute_metrics(bl_outcomes),
                         population=len(profiles))
