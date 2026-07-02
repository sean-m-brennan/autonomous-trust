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
"""Resilience/threat modeling-and-simulation red-team suite (SOW Task 3.4).

Pure, deterministic, library-level M&S for the behavioural-anomaly layer: a
synthetic peer population across the threat archetypes is driven through the
``BehaviorMonitor`` and a static-policy baseline, and the run reports detection
latency, exclusion correctness, and the false-exclusion rate projected to a
realistic attack base rate (Axelsson). No node/network/docker dependency.
"""
from .archetypes import (ARCHETYPES, ADVERSARY_ARCHETYPES, PeerProfile,
                         BENIGN, COMPROMISED_CREDENTIAL, BYZANTINE, SYBIL, DDIL,
                         generate_stream)
from .baseline import StaticPolicyDetector
from .metrics import DetectorMetrics, PeerOutcome, compute_metrics
from .harness import RedTeamConfig, RedTeamResult, build_population, run

__all__ = ['ARCHETYPES', 'ADVERSARY_ARCHETYPES', 'PeerProfile',
           'BENIGN', 'COMPROMISED_CREDENTIAL', 'BYZANTINE', 'SYBIL', 'DDIL',
           'generate_stream', 'StaticPolicyDetector', 'DetectorMetrics',
           'PeerOutcome', 'compute_metrics', 'RedTeamConfig', 'RedTeamResult',
           'build_population', 'run']
