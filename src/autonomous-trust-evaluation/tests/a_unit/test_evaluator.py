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

import pytest

try:
    from autonomous_trust.evaluation.covenant.evaluator import compute_fitness
    _has_covenant = True
except ImportError:
    _has_covenant = False

pytestmark = pytest.mark.skipif(not _has_covenant,
                                reason='covenant package not installed')


class TestComputeFitness:
    def _full_observer(self, **overrides):
        base = {
            'cooperation_rate': 1.0,
            'task_throughput': 1.0,
            'policy_compliance_rate': 1.0,
        }
        base.update(overrides)
        return base

    def _full_metrics(self, **overrides):
        base = {
            'identity_convergence_s': 0.0,
            'reputation_stability_stddev': 0.0,
            'bandwidth_overhead_fraction': 0.0,
        }
        base.update(overrides)
        return base

    def test_perfect_scores(self):
        score = compute_fitness(self._full_observer(), self._full_metrics())
        assert score == pytest.approx(1.0, abs=1e-9)

    def test_all_none_scores_zero(self):
        score = compute_fitness({}, {})
        assert score == pytest.approx(0.0, abs=1e-9)

    def test_cooperation_rate_only(self):
        obs = {'cooperation_rate': 0.8}
        score = compute_fitness(obs, {})
        # 0.30 * 0.8 = 0.24
        assert score == pytest.approx(0.24, abs=1e-9)

    def test_inverted_metric_identity_convergence(self):
        obs = self._full_observer()
        met = self._full_metrics(identity_convergence_s=60.0)
        score = compute_fitness(obs, met)
        # identity_convergence: 1 - 60/120 = 0.5, weight 0.15 -> 0.075
        # Perfect for everything else: 0.85 + 0.075 = 0.925
        expected = 1.0 - 0.15 * 0.5
        assert score == pytest.approx(expected, abs=1e-9)

    def test_inverted_metric_clamped_at_max(self):
        met = self._full_metrics(identity_convergence_s=999.0)
        score = compute_fitness(self._full_observer(), met)
        # identity_convergence: 1 - min(999/120, 1.0) = 0, weight 0.15
        expected = 1.0 - 0.15
        assert score == pytest.approx(expected, abs=1e-9)

    def test_bandwidth_overhead(self):
        met = self._full_metrics(bandwidth_overhead_fraction=0.5)
        score = compute_fitness(self._full_observer(), met)
        # bandwidth: 1 - 0.5/1.0 = 0.5, weight 0.05 -> 0.025
        expected = 1.0 - 0.05 * 0.5
        assert score == pytest.approx(expected, abs=1e-9)

    def test_custom_weights(self):
        weights = {'cooperation_rate': 1.0}  # only weight
        obs = {'cooperation_rate': 0.6}
        score = compute_fitness(obs, {}, weights=weights)
        assert score == pytest.approx(0.6, abs=1e-9)

    def test_throughput_normalization(self):
        obs = {'task_throughput': 2.0}
        score = compute_fitness(obs, {}, max_throughput=2.0)
        # 2.0/2.0 = 1.0, clamped to 1.0, weight 0.10
        assert score == pytest.approx(0.10, abs=1e-9)

    def test_throughput_clamped_at_one(self):
        obs = {'task_throughput': 100.0}
        score = compute_fitness(obs, {}, max_throughput=1.0)
        # min(100/1, 1.0) = 1.0, weight 0.10
        assert score == pytest.approx(0.10, abs=1e-9)

    def test_weights_sum(self):
        """Default weights should sum to 1.0."""
        from autonomous_trust.evaluation.covenant.evaluator import _DEFAULT_WEIGHTS
        assert sum(_DEFAULT_WEIGHTS.values()) == pytest.approx(1.0, abs=1e-9)

    def test_partial_observer_report(self):
        obs = {
            'cooperation_rate': 0.5,
            'policy_compliance_rate': 0.8,
        }
        score = compute_fitness(obs, {})
        expected = 0.30 * 0.5 + 0.25 * 0.8
        assert score == pytest.approx(expected, abs=1e-9)

    def test_reputation_stability(self):
        met = self._full_metrics(reputation_stability_stddev=0.25)
        score = compute_fitness(self._full_observer(), met)
        # rep_stability: 1 - 0.25/0.5 = 0.5, weight 0.15
        expected = 1.0 - 0.15 * 0.5
        assert score == pytest.approx(expected, abs=1e-9)
