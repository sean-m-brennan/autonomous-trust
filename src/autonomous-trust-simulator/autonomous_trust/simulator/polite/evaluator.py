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

"""PoliteEvaluator: orchestrates policy evaluation with fitness scoring.

Provides compute_fitness() for scoring and two evaluation backends:
InProcessEvaluator (fast, mock peers) and DockerEvaluator (full simulation).
"""

import json
import os
import subprocess
import tempfile
from typing import Optional

from polite.interface import EvaluatorResult
from polite.policy import PolitePolicy


# Default normalization bounds
_DEFAULT_MAX_CONVERGENCE_S = 120.0
_DEFAULT_MAX_STDDEV = 0.5
_DEFAULT_MAX_FRACTION = 1.0
_DEFAULT_MAX_THROUGHPUT = 1.0

# Default weights (sum to 1.0)
_DEFAULT_WEIGHTS = {
    'cooperation_rate': 0.30,
    'task_throughput': 0.10,
    'policy_compliance_rate': 0.25,
    'identity_convergence': 0.15,
    'reputation_stability': 0.15,
    'bandwidth_overhead': 0.05,
}


def compute_fitness(
    observer_report: dict,
    metrics_report: dict,
    weights: Optional[dict] = None,
    max_convergence_s: float = _DEFAULT_MAX_CONVERGENCE_S,
    max_stddev: float = _DEFAULT_MAX_STDDEV,
    max_fraction: float = _DEFAULT_MAX_FRACTION,
    max_throughput: float = _DEFAULT_MAX_THROUGHPUT,
) -> float:
    """Compute weighted fitness score from observer and metrics reports.

    Each metric is normalized to [0, 1] before weighting.
    None values score 0.
    """
    w = weights or _DEFAULT_WEIGHTS

    def _val(d, key):
        """Return the value or None (preserving None for callers)."""
        return d.get(key)

    def _direct(d, key):
        """Return value in [0,1]; None maps to 0."""
        v = _val(d, key)
        return v if v is not None else 0.0

    def _inverted(d, key, max_val):
        """Return 1 - normalized_value; None maps to 0."""
        v = _val(d, key)
        if v is None:
            return 0.0
        return 1.0 - min(v / max_val, 1.0)

    scores = {
        'cooperation_rate': _direct(observer_report, 'cooperation_rate'),
        'task_throughput': min(
            _direct(observer_report, 'task_throughput') / max_throughput, 1.0),
        'policy_compliance_rate': _direct(
            observer_report, 'policy_compliance_rate'),
        'identity_convergence': _inverted(
            metrics_report, 'identity_convergence_s', max_convergence_s),
        'reputation_stability': _inverted(
            metrics_report, 'reputation_stability_stddev', max_stddev),
        'bandwidth_overhead': _inverted(
            metrics_report, 'bandwidth_overhead_fraction', max_fraction),
    }

    return sum(w.get(k, 0.0) * v for k, v in scores.items())


class InProcessEvaluator:
    """Fast in-process evaluation using mock peers."""

    def __init__(self, duration_s: float = 30.0, **fitness_kwargs):
        self._duration_s = duration_s
        self._fitness_kwargs = fitness_kwargs

    def evaluate(self, policy: PolitePolicy) -> EvaluatorResult:
        from autonomous_trust.simulator.polite.instrumented import (
            PoliteInstrumentedAT,
        )

        with tempfile.TemporaryDirectory() as td:
            metrics_path = os.path.join(td, 'metrics.json')
            observer_path = os.path.join(td, 'polite.json')

            PoliteInstrumentedAT._metrics_output = metrics_path
            PoliteInstrumentedAT._polite_policy = policy
            PoliteInstrumentedAT._polite_output = observer_path

            try:
                at = PoliteInstrumentedAT(multiproc=True, testing=True)
                at.run_forever()
            except (KeyboardInterrupt, SystemExit):
                pass
            finally:
                PoliteInstrumentedAT._metrics_output = None
                PoliteInstrumentedAT._polite_policy = None
                PoliteInstrumentedAT._polite_output = None

            metrics_report = {}
            if os.path.exists(metrics_path):
                with open(metrics_path) as f:
                    metrics_report = json.load(f)

            observer_report = {}
            if os.path.exists(observer_path):
                with open(observer_path) as f:
                    observer_report = json.load(f)

            score = compute_fitness(
                observer_report, metrics_report, **self._fitness_kwargs)
            return EvaluatorResult(
                policy=policy,
                observer_report=observer_report,
                metrics_report=metrics_report,
                fitness_score=score,
            )


class DockerEvaluator:
    """Run full Docker simulation with a policy and collect results."""

    def __init__(self, script_path: str, **kwargs):
        self._script = script_path
        self._extra_args = kwargs

    def evaluate(self, policy: PolitePolicy) -> EvaluatorResult:
        with tempfile.TemporaryDirectory() as td:
            policy_path = os.path.join(td, 'policy.json')
            with open(policy_path, 'w') as f:
                json.dump(policy.to_dict(), f)

            metrics_path = os.path.join(td, 'metrics.json')
            observer_path = os.path.join(td, 'polite.json')

            cmd = [
                'bash', self._script,
                '--python', '--quick',
                '--polite-policy', policy_path,
                '--polite-output', observer_path,
                '--output', metrics_path,
            ]
            subprocess.run(cmd, check=True, capture_output=True)

            metrics_report = {}
            if os.path.exists(metrics_path):
                with open(metrics_path) as f:
                    metrics_report = json.load(f)

            observer_report = {}
            if os.path.exists(observer_path):
                with open(observer_path) as f:
                    observer_report = json.load(f)

            score = compute_fitness(observer_report, metrics_report)
            return EvaluatorResult(
                policy=policy,
                observer_report=observer_report,
                metrics_report=metrics_report,
                fitness_score=score,
            )
