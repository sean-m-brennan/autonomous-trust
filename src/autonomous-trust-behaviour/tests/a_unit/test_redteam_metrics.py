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
"""Pure unit tests for the M&S metrics + archetypes (SOW Task 3.4). Fast: no
detector run. Pins the confusion-matrix math and the base-rate (Axelsson)
projection that the resilience claim rests on."""
import random

import pytest

from autonomous_trust.behaviour.redteam import (
    BENIGN, COMPROMISED_CREDENTIAL, DDIL, SYBIL, PeerProfile, compute_metrics,
    generate_stream)
from autonomous_trust.behaviour.redteam.metrics import DetectorMetrics, make_outcome
from autonomous_trust.behaviour.redteam.archetypes import onset_time, NORMAL_CAPS


class TestDetectorMetrics:
    def test_rates(self):
        m = DetectorMetrics(tp=9, fp=10, fn=1, tn=90)
        assert m.tpr == pytest.approx(0.9)            # 9/10
        assert m.fpr == pytest.approx(0.1)            # 10/100
        assert m.false_exclusion_rate == m.fpr        # SOW wording alias
        assert m.ppv == pytest.approx(9 / 19)
        assert m.fdr == pytest.approx(10 / 19)

    def test_ppv_at_base_rate_axelsson(self):
        # tpr=0.9, fpr=0.1: at a 1% base rate precision collapses far below the
        # observed-mix precision -- the base-rate fallacy, quantified.
        m = DetectorMetrics(tp=9, fp=10, fn=1, tn=90)
        # 0.01*0.9 / (0.01*0.9 + 0.99*0.1) = 0.009/0.108
        assert m.ppv_at_base_rate(0.01) == pytest.approx(0.009 / 0.108, abs=1e-6)
        assert m.ppv_at_base_rate(0.05) > m.ppv_at_base_rate(0.01)

    def test_zero_false_positive_keeps_precision_at_any_base_rate(self):
        # The discipline payoff: FPR==0 -> precision is 1.0 regardless of how
        # rare attackers are (the property the governed ML sensor achieves).
        m = DetectorMetrics(tp=5, fp=0, fn=5, tn=100)
        assert m.fpr == 0.0
        assert m.ppv_at_base_rate(0.01) == pytest.approx(1.0)
        assert m.ppv_at_base_rate(1e-6) == pytest.approx(1.0)

    def test_empty_is_safe(self):
        m = DetectorMetrics(tp=0, fp=0, fn=0, tn=0)
        assert m.tpr == 0.0 and m.fpr == 0.0 and m.ppv == 0.0
        assert m.ppv_at_base_rate(0.01) == 0.0
        assert m.latency_mean is None

    def test_compute_metrics_and_per_archetype(self):
        profiles = [
            PeerProfile('c0', 'peer', COMPROMISED_CREDENTIAL, True, 10),
            PeerProfile('c1', 'peer', COMPROMISED_CREDENTIAL, True, 10),
            PeerProfile('b0', 'peer', BENIGN, False, None),
            PeerProfile('d0', 'peer', DDIL, False, 10),
        ]
        outcomes = [
            make_outcome(profiles[0], True, 5.0, 9.0),    # TP, latency 4
            make_outcome(profiles[1], False, 5.0, None),  # FN
            make_outcome(profiles[2], False, None, None),  # TN
            make_outcome(profiles[3], True, 5.0, 8.0),    # FP (benign DDIL)
        ]
        m = compute_metrics(outcomes)
        assert (m.tp, m.fn, m.tn, m.fp) == (1, 1, 1, 1)
        assert m.detection_latencies == [4.0]
        assert m.archetype_detection_rate(COMPROMISED_CREDENTIAL) == 0.5
        assert m.archetype_detection_rate(DDIL) == 1.0    # false-exclusion
        assert m.as_dict()['ppv_at_base_rate']['0.01'] is not None


class TestArchetypes:
    def test_generate_stream_is_deterministic(self):
        prof = PeerProfile('x', 'peer', COMPROMISED_CREDENTIAL, True, 20)
        a = generate_stream(prof, random.Random(1), 60)
        b = generate_stream(prof, random.Random(1), 60)
        assert [(e.capability, e.refused, e.score) for e in a] == \
               [(e.capability, e.refused, e.score) for e in b]

    def test_onset_switches_behaviour(self):
        prof = PeerProfile('x', 'peer', COMPROMISED_CREDENTIAL, True, 30)
        stream = generate_stream(prof, random.Random(2), 60)
        # pre-onset is benign cover (known caps), post-onset is probing
        assert stream[0].capability in NORMAL_CAPS
        assert any(e.capability.startswith('probe-') for e in stream[30:])
        assert all(not e.capability.startswith('probe-') for e in stream[:30])

    def test_onset_time_none_for_benign(self):
        prof = PeerProfile('b', 'peer', BENIGN, False, None)
        assert onset_time(prof, generate_stream(prof, random.Random(3), 20)) is None

    def test_sybil_is_footprint_from_start(self):
        prof = PeerProfile('s', 'peer', SYBIL, True, 0)
        stream = generate_stream(prof, random.Random(4), 20)
        # templated: single capability + single counterparty throughout
        assert {e.capability for e in stream} == {'telemetry.report'}
        assert {e.counterparty for e in stream} == {'peer-A'}
