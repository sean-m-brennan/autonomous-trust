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
"""AutonomousTrust behavioral-anomaly layer (SOW Task 3 / objective O3).

An in-built, on-node streaming anomaly scorer that feeds the existing
deterministic reputation/slashing/tier-gating engine as *governed evidence* --
"ML proposes, deterministic consensus disposes". Every detector here is

  * **online / streaming** -- incremental per-event update, no batch retrain;
  * **unsupervised** -- no labeled attack data;
  * **bounded-memory** -- runs on each node including embedded ARM;
  * **deterministic under a fixed seed** -- the score becomes signed evidence in
    the consensus ledger, so it must be bit-reproducible across nodes (this is
    what makes it admissible rather than a black box); and
  * **explainable** -- per-feature attribution of *why* something is anomalous.

The Phase-I prototype builds the detectors **via River/PyOD** — the mature,
permissively-licensed reference runtimes named in the SOW (Task 3.2) and the
AI/ML survey (``doc/NV059/work/AIML_software_survey.md`` §2): the multivariate
isolation score from ``river.anomaly.HalfSpaceTrees`` and the per-feature,
explainable histogram score from ``pyod.models.hbos.HBOS`` (made streaming via a
sliding-window refit). Both are deterministic under a fixed seed. The deferred
formally-verified C core is the "owned" reimplementation, pinned to this
prototype by the cross-language conformance corpus (Task 3.5).
"""
# The pure, node-agnostic library (the future standalone .so): detectors,
# features, the per-peer×role engine, and its neutral SlashProposal output. No
# dependency on autonomous_trust.core -- importable on its own (e.g. for the
# C-port conformance corpus).
from .detectors import (RiverHalfSpaceTrees, PyODHBOS, StreamingCalibrator,
                        AnomalyDetector)
from .features import AccessEvent, BehaviorFeatures, FEATURE_NAMES
from .ensemble import (AnomalyDecision, BehaviorMonitor, PeerRoleDetector,
                       SlashProposal, REASON_SUSTAINED_ANOMALY)

__all__ = ['RiverHalfSpaceTrees', 'PyODHBOS', 'StreamingCalibrator',
           'AnomalyDetector', 'AccessEvent', 'BehaviorFeatures', 'FEATURE_NAMES',
           'AnomalyDecision', 'BehaviorMonitor', 'PeerRoleDetector',
           'SlashProposal', 'REASON_SUSTAINED_ANOMALY']

# The host-side adapter (the governed path, B4) translates proposals into core
# SlashAttestations, so it imports autonomous_trust.core -- present only when the
# sibling `autonomous-trust` package is on the path. Export it best-effort so the
# pure library above stays importable without core.
try:  # pragma: no cover - exercised by both branches across environments
    from .governor import (PeerBehaviourGovernor, SlashRecommendation,
                           DEFAULT_SLASH_FLOOR)
    __all__ += ['PeerBehaviourGovernor', 'SlashRecommendation',
                'DEFAULT_SLASH_FLOOR']
except ImportError:  # core package not importable in this environment
    pass
