"""Red team harness: orchestrate attack scenarios against AT simulation."""

import json
import os
import subprocess
import sys
from datetime import datetime
from typing import Optional

from . import AttackScenario


class RedTeamHarness:
    """Orchestrates adversarial testing against AT simulation.

    1. Loads Phase 2 baseline metrics for comparison.
    2. Calls setup() on each AttackScenario to modify config.
    3. Launches simulation via test-simulation-scenarios.sh.
    4. Collects metrics and calls collect() on each scenario.
    5. Compares against baseline and outputs report.
    6. Always calls teardown() in a finally block.
    """

    def __init__(self, baseline_path: str, scenarios: list[AttackScenario]):
        self.baseline_path = baseline_path
        self.scenarios = scenarios
        self._baseline: Optional[dict] = None

    def _load_baseline(self) -> dict:
        if self._baseline is None:
            with open(self.baseline_path) as f:
                self._baseline = json.load(f)
        return self._baseline

    def run(self, output_path: str, quick: bool = True,
            timeout_s: Optional[int] = None) -> dict:
        """Run all attack scenarios and produce a report.

        Args:
            output_path: Where to write the JSON report.
            quick: Use --quick flag for test-simulation-scenarios.sh.
            timeout_s: Wall-clock timeout. Default: quick duration + 60s.
        """
        if timeout_s is None:
            timeout_s = 240 if quick else 3660

        sim_config = {}
        compose_config = {}

        try:
            for scenario in self.scenarios:
                scenario.setup(sim_config, compose_config)

            attack_metrics = self._run_simulation(quick=quick, timeout_s=timeout_s,
                                                  sim_config=sim_config)
            report = self.build_report(attack_metrics=attack_metrics)

        except Exception:
            raise
        finally:
            for scenario in self.scenarios:
                try:
                    scenario.teardown()
                except Exception:
                    pass

        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)

        # Also write markdown report
        from .report import generate_markdown_report
        md_path = output_path.rsplit('.', 1)[0] + '.md'
        md_content = generate_markdown_report(report)
        with open(md_path, 'w') as f:
            f.write(md_content)

        return report

    def _run_simulation(self, quick: bool, timeout_s: int,
                        sim_config: dict) -> dict:
        """Launch test-simulation-scenarios.sh and collect metrics."""
        script_dir = os.path.join(
            os.path.dirname(__file__), '..', '..', '..', '..',
            'config')
        script = os.path.join(script_dir, 'test-simulation-scenarios.sh')

        cmd = ['bash', script]
        if quick:
            cmd.append('--quick')
        cmd.extend(['--output', '/tmp/redteam-metrics.json'])

        if 'router_class' in sim_config:
            env = os.environ.copy()
            env['REDTEAM_ATTACK_ROUTER'] = '1'
            if 'router_kwargs' in sim_config:
                env['REDTEAM_PARTITIONS'] = json.dumps([
                    {'start_s': p.start_s, 'end_s': p.end_s,
                     'group_a': p.group_a, 'group_b': p.group_b}
                    for p in sim_config['router_kwargs'].get('partitions', [])
                ])
        else:
            env = None

        try:
            result = subprocess.run(cmd, timeout=timeout_s, env=env,
                                    capture_output=True, text=True)
        except subprocess.TimeoutExpired:
            return {'error': 'timeout', 'timeout_s': timeout_s}

        if os.path.exists('/tmp/redteam-metrics.json'):
            with open('/tmp/redteam-metrics.json') as f:
                return json.load(f)

        return {'error': 'no_metrics', 'returncode': result.returncode,
                'stderr': result.stderr[-500:] if result.stderr else ''}

    def build_report(self, attack_metrics: dict) -> dict:
        """Build the consolidated report from baseline + attack metrics."""
        baseline = self._load_baseline()

        attacks = []
        for scenario in self.scenarios:
            enriched = scenario.collect(dict(attack_metrics))
            result = self._assess_result(baseline, enriched)
            attacks.append({
                'name': scenario.name,
                'description': scenario.description,
                'metrics_during_attack': {
                    k: v for k, v in enriched.items()
                    if k in baseline
                },
                'attack_specific': enriched.get('attack_specific', {}),
                'result': result,
            })

        passed = sum(1 for a in attacks if a['result'] == 'PASS')
        failed = sum(1 for a in attacks if a['result'] == 'FAIL')
        errors = sum(1 for a in attacks if a['result'] in ('ERROR', 'NO_DATA'))

        return {
            'timestamp': datetime.utcnow().isoformat(),
            'baseline': baseline,
            'attacks': attacks,
            'summary': {
                'total': len(attacks),
                'passed': passed,
                'failed': failed,
                'errors': errors,
            },
        }

    def _assess_result(self, baseline: dict, attack_metrics: dict) -> str:
        """Compare attack metrics to baseline. Return PASS/FAIL/ERROR/NO_DATA."""
        if 'error' in attack_metrics:
            if attack_metrics['error'] == 'no_metrics':
                return 'NO_DATA'
            return 'ERROR'

        conv_b = baseline.get('identity_convergence_s')
        conv_a = attack_metrics.get('identity_convergence_s')
        if conv_b is not None and conv_a is not None:
            if conv_a > conv_b * 3:
                return 'FAIL'

        rep_a = attack_metrics.get('reputation_stability_stddev')
        if rep_a is not None:
            if rep_a > 0.15:
                return 'FAIL'

        return 'PASS'
