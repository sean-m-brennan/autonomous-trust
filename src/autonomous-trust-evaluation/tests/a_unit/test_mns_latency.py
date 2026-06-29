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
"""Unit tests for the AT-vs-ZTA access-decision latency M&S (SOW Task 2.4).

The model is pure stdlib + deterministic; these tests pin determinism, the
structural AT<ZTA ordering, the -50% target across link profiles, and the
contention monotonicity."""
from autonomous_trust.evaluation.mns.latency import (
    LatencyConfig, LinkModel, PROFILES, run, sweep)


def test_deterministic_under_seed():
    a = run(LatencyConfig(seed=99, trials=2000))
    b = run(LatencyConfig(seed=99, trials=2000))
    assert a.zta.mean_ms == b.zta.mean_ms
    assert a.at.mean_ms == b.at.mean_ms


def test_at_local_far_below_zta_on_tactical():
    r = run(LatencyConfig(seed=1234))          # default = tactical link
    assert r.at.mean_ms < r.zta.mean_ms
    assert r.meets_target                       # >= 50% mean reduction
    assert r.reduction_mean > 0.9               # dramatic on a contested link


def test_meets_target_across_all_profiles_even_favorable_zta():
    # Even ZTA's best case (stapled OCSP, no extra revocation RTT) on the most
    # benign link must still show >50% -- AT avoids the round-trip entirely.
    for row in sweep(base=LatencyConfig(seed=7, trials=3000)):
        assert row.reduction_mean >= 0.50, (row.profile, row.favorable_zta,
                                            row.reduction_mean)


def test_benign_lan_is_the_honest_floor():
    # The benign-LAN favorable-ZTA case is the smallest reduction; contested is
    # larger. Demonstrates the model responds to link adversity (not flat).
    rows = sweep(base=LatencyConfig(seed=7, trials=3000))
    benign_fav = next(r for r in rows if r.profile == 'benign-LAN' and r.favorable_zta)
    tactical_base = next(r for r in rows if r.profile == 'tactical' and not r.favorable_zta)
    assert benign_fav.reduction_mean < tactical_base.reduction_mean


def test_at_local_is_cohort_independent_but_zta_is_not():
    small = run(LatencyConfig(seed=5, cohort_size=10, trials=3000))
    large = run(LatencyConfig(seed=5, cohort_size=95, trials=3000))
    # AT-local has no shared bottleneck -> flat in cohort size.
    assert abs(small.at.mean_ms - large.at.mean_ms) < 0.05
    # ZTA shares the PDP -> queueing grows with cohort.
    assert large.zta.mean_ms > small.zta.mean_ms


def test_favorable_zta_is_faster_than_baseline_zta():
    base = run(LatencyConfig(seed=3, separate_revocation_rtt=True, trials=3000))
    fav = run(LatencyConfig(seed=3, separate_revocation_rtt=False, trials=3000))
    assert fav.zta.mean_ms < base.zta.mean_ms   # dropping the OCSP RTT helps ZTA


def test_report_shape():
    rep = run(LatencyConfig(seed=1)).as_report()
    assert rep['modeled'] is True
    assert rep['meets_50pct_target'] in (True, False)
    for key in ('zta_pdp', 'at_local', 'reduction_mean', 'reduction_p95'):
        assert key in rep
    assert set(PROFILES) == {'benign-LAN', 'garrison-WAN', 'tactical', 'DDIL-severe'}
