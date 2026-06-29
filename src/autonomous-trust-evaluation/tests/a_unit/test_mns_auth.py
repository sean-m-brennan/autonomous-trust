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
"""Unit tests for the auth-time M&S (SOW Task 2.4, Auth <=5s)."""
from autonomous_trust.evaluation.mns.auth import AuthConfig, run


def test_deterministic_under_seed():
    a, b = run(AuthConfig(seed=5)), run(AuthConfig(seed=5))
    assert a.reauth_worst_p95 == b.reauth_worst_p95
    assert a.enroll.p95_ms == b.enroll.p95_ms
    assert a.degraded_with_base2.p95_ms == b.degraded_with_base2.p95_ms


def test_steady_state_reauth_passes_gate_and_is_flat_in_cohort():
    r = run(AuthConfig(seed=1234))
    assert r.reauth_passes                      # worst p95 < 5 s
    p95s = [row['at'].p95_ms for row in r.reauth]
    assert max(p95s) - min(p95s) < 100.0        # AT is local -> flat in cohort
    # At the largest cohort, AT (local) is no slower than the shared-PDP baseline.
    last = r.reauth[-1]
    assert last['at'].p95_ms <= last['zta'].p95_ms


def test_enrollment_characterized_reasonable():
    r = run(AuthConfig(seed=1234))
    assert 0.0 < r.enroll.mean_ms < r.enroll.p95_ms     # a real distribution


def test_degraded_edge_at_passes_but_strict_zta_busts_gate():
    r = run(AuthConfig(seed=1234))
    assert r.degraded_passes                    # AT p95 < 5 s via fallback
    assert r.degraded_with_base2.p95_ms < r.config.gate_ms
    assert not r.strict_zta_degraded_passes     # strict ZTA blocks > 5 s


def test_base2_attestation_adds_latency():
    r = run(AuthConfig(seed=1234))
    assert r.degraded_with_base2.mean_ms > r.degraded_no_base2.mean_ms


def test_report_shape():
    rep = run(AuthConfig(seed=1)).as_report()
    assert rep['modeled'] is True
    assert rep['reauth_steady_state']['gated'] is True
    assert rep['enrollment_one_time']['gated'] is False
    assert rep['degraded_edge_first_contact']['at_passes_5s'] in (True, False)
    assert rep['degraded_edge_first_contact']['strict_zta_passes_5s'] is False
