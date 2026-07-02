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
"""Unit tests for the streaming anomaly detectors (SOW Task 3.2), built via
River/PyOD.

The load-bearing property is **determinism**: the score becomes signed evidence
in the consensus ledger, so the same seed + the same stream must yield the same
score. River's Half-Space Trees is deterministic given a seed; PyOD's HBOS has
no randomness at all. These tests pin that, plus anomaly separation, HBOS
per-feature attribution, and warmup semantics.
"""
import random

import pytest

from autonomous_trust.behaviour import RiverHalfSpaceTrees, PyODHBOS, StreamingCalibrator

NAMES = ('a', 'b', 'c', 'd')


def _cluster(rng, n, dim=4, center=0.5, spread=0.05):
    return [[min(1.0, max(0.0, rng.gauss(center, spread))) for _ in range(dim)]
            for _ in range(n)]


# --------------------------------------------------------------------------
# River Half-Space Trees
# --------------------------------------------------------------------------

class TestRiverHalfSpaceTrees:
    def test_seed_determinism_exact(self):
        rng = random.Random(1)
        stream = _cluster(rng, 300)
        probe = [0.95, 0.95, 0.95, 0.95]

        def run():
            d = RiverHalfSpaceTrees(NAMES, n_trees=10, height=8,
                                    window_size=50, seed=42)
            scores = [d.score_partial_fit(x) for x in stream]
            return scores, d.score_one(probe)

        a_scores, a_probe = run()
        b_scores, b_probe = run()
        assert a_scores == b_scores          # exact equality
        assert a_probe == b_probe

    def test_outlier_scores_higher(self):
        rng = random.Random(7)
        d = RiverHalfSpaceTrees(NAMES, n_trees=15, height=10, window_size=50,
                                seed=3)
        for x in _cluster(rng, 400):
            d.learn_one(x)
        assert d.warm
        assert d.score_one([0.97, 0.03, 0.97, 0.03]) > d.score_one([0.5, 0.5, 0.5, 0.5])

    def test_warm_after_window(self):
        d = RiverHalfSpaceTrees(NAMES, n_trees=5, height=6, window_size=40, seed=0)
        assert d.warm is False
        for _ in range(40):
            d.learn_one([0.5, 0.5, 0.5, 0.5])
        assert d.warm is True

    def test_score_in_unit_interval(self):
        rng = random.Random(3)
        d = RiverHalfSpaceTrees(NAMES, n_trees=10, height=8, window_size=50, seed=11)
        for x in _cluster(rng, 200):
            s = d.score_partial_fit(x)
            assert 0.0 <= s <= 1.0


# --------------------------------------------------------------------------
# PyOD HBOS (sliding-window streaming adapter)
# --------------------------------------------------------------------------

HBOS_KW = dict(n_bins=20, window=150, refit_every=25, warmup=60)


class TestPyODHBOS:
    def test_no_randomness_deterministic(self):
        rng = random.Random(5)
        stream = _cluster(rng, 200)
        probe = [0.9, 0.1, 0.5, 0.5]

        def run():
            d = PyODHBOS(NAMES, **HBOS_KW)
            scores = [d.score_partial_fit(x) for x in stream]
            return scores, d.score_one(probe), d.attributions(probe)

        a_scores, a_probe, a_attr = run()
        b_scores, b_probe, b_attr = run()
        assert a_scores == b_scores
        assert a_probe == b_probe
        assert a_attr == b_attr

    def test_outlier_scores_higher(self):
        rng = random.Random(9)
        d = PyODHBOS(NAMES, **HBOS_KW)
        for x in _cluster(rng, 300):
            d.learn_one(x)
        assert d.warm
        assert d.score_one([0.97, 0.97, 0.03, 0.03]) > d.score_one([0.5, 0.5, 0.5, 0.5])

    def test_attribution_points_at_the_anomalous_feature(self):
        rng = random.Random(2)
        names = ('rate', 'burst', 'refusal', 'diversity')
        d = PyODHBOS(names, **HBOS_KW)
        for x in _cluster(rng, 300):
            d.learn_one(x)
        # only 'refusal' (index 2) is anomalous; the rest sit at the mode
        probe = [0.5, 0.5, 0.98, 0.5]
        top = d.top_features(probe, k=1)
        assert top[0][0] == 'refusal'
        attribs = d.attributions(probe)
        # the tail value is (near-)unseen -> high rarity; it dominates the
        # at-mode features by a wide margin (PyOD bins span the window range, so
        # an at-mode value need not sit exactly in the modal bin).
        assert attribs['refusal'] > 0.8
        assert attribs['refusal'] > attribs['rate'] + 0.4
        assert all(attribs['refusal'] > attribs[f]
                   for f in ('rate', 'burst', 'diversity'))

    def test_cold_start_not_warm_no_attribution(self):
        d = PyODHBOS(NAMES, **HBOS_KW)
        assert d.warm is False
        assert d.score_one([0.5, 0.5, 0.5, 0.5]) == 0.0
        assert d.attributions([0.5, 0.5, 0.5, 0.5]) == {}
        rng = random.Random(0)
        for x in _cluster(rng, 80):
            d.learn_one(x)
        assert d.warm is True
        assert d.attributions([0.5, 0.5, 0.5, 0.5]) != {}


# --------------------------------------------------------------------------
# Calibrator
# --------------------------------------------------------------------------

class TestStreamingCalibrator:
    def test_deterministic(self):
        seq = [0.1, 0.2, 0.15, 0.3, 0.25, 0.2, 0.9, 0.1, 0.05, 0.2] * 10
        a, b = StreamingCalibrator(warmup=20), StreamingCalibrator(warmup=20)
        out_a = [a.calibrate_partial_fit(s) for s in seq]
        out_b = [b.calibrate_partial_fit(s) for s in seq]
        assert out_a == out_b

    def test_warmup_passthrough_then_calibrates(self):
        c = StreamingCalibrator(warmup=10, k=1.0)
        rng = random.Random(4)
        for s in (rng.gauss(0.2, 0.05) for _ in range(200)):
            c.update(s)
        assert c.calibrate(0.9) > 0.9
        assert c.calibrate(c.mean) == pytest.approx(0.5, abs=0.01)

    def test_monotonic_in_raw(self):
        c = StreamingCalibrator(warmup=5)
        rng = random.Random(1)
        for _ in range(200):
            c.update(rng.gauss(0.3, 0.1))
        assert c.calibrate(0.2) < c.calibrate(0.4) < c.calibrate(0.8)

    def test_zero_variance_baseline(self):
        c = StreamingCalibrator(warmup=5)
        for _ in range(10):
            c.update(0.5)
        assert c.calibrate(0.6) == 1.0
        assert c.calibrate(0.4) == 0.0

    def test_not_warm_passthrough_clamped(self):
        c = StreamingCalibrator(warmup=10)
        assert c.calibrate(1.5) == 1.0
        assert c.calibrate(-0.3) == 0.0
        assert c.calibrate(0.4) == 0.4

    def test_min_std_floor_prevents_hair_trigger(self):
        # With a tight (near-constant) baseline, a std floor keeps a tiny
        # deviation from calibrating to ~1.0 (the base-rate guard).
        floored = StreamingCalibrator(warmup=5, min_std=0.1)
        plain = StreamingCalibrator(warmup=5, min_std=0.0)
        rng = random.Random(2)
        for _ in range(100):
            s = rng.gauss(0.1, 0.001)   # almost constant
            floored.update(s)
            plain.update(s)
        # a small absolute deviation: floored stays moderate, plain saturates
        assert floored.calibrate(0.2) < 0.95
        assert plain.calibrate(0.2) > 0.99
