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
"""Tests for PoliteEvaluator fitness scoring."""

import pytest

try:
    from polite.policy import null_policy, strict_policy
    from polite.interface import EvaluatorResult
except ImportError:
    pytest.skip("polite package not on PYTHONPATH", allow_module_level=True)

from autonomous_trust.simulator.polite.evaluator import compute_fitness


class TestFitnessFunction:

    def test_perfect_scores(self):
        observer = {
            'cooperation_rate': 1.0,
            'task_throughput': 1.0,
            'policy_compliance_rate': 1.0,
        }
        metrics = {
            'identity_convergence_s': 0.0,
            'reputation_stability_stddev': 0.0,
            'bandwidth_overhead_fraction': 0.0,
        }
        score = compute_fitness(observer, metrics)
        assert score == pytest.approx(1.0)

    def test_zero_scores(self):
        observer = {
            'cooperation_rate': 0.0,
            'task_throughput': 0.0,
            'policy_compliance_rate': 0.0,
        }
        metrics = {
            'identity_convergence_s': 120.0,
            'reputation_stability_stddev': 0.5,
            'bandwidth_overhead_fraction': 1.0,
        }
        score = compute_fitness(observer, metrics)
        assert score == pytest.approx(0.0)

    def test_none_metrics_score_zero(self):
        observer = {
            'cooperation_rate': None,
            'task_throughput': None,
            'policy_compliance_rate': None,
        }
        metrics = {
            'identity_convergence_s': None,
            'reputation_stability_stddev': None,
            'bandwidth_overhead_fraction': None,
        }
        score = compute_fitness(observer, metrics)
        assert score == 0.0

    def test_strict_vs_null_policy_different_scores(self):
        high = {
            'cooperation_rate': 0.9,
            'task_throughput': 0.5,
            'policy_compliance_rate': 0.95,
        }
        low = {
            'cooperation_rate': 0.4,
            'task_throughput': 0.1,
            'policy_compliance_rate': 0.3,
        }
        metrics = {
            'identity_convergence_s': 30.0,
            'reputation_stability_stddev': 0.02,
            'bandwidth_overhead_fraction': 0.1,
        }
        high_score = compute_fitness(high, metrics)
        low_score = compute_fitness(low, metrics)
        assert high_score > low_score
