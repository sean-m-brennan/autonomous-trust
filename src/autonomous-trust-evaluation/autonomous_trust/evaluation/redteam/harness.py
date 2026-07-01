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
"""Red team harness: orchestrate attack scenarios against AT simulation."""

import json
import os
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone
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
            timeout_s: Optional[int] = None,
            caldera: bool = False) -> dict:
        """Run all attack scenarios and produce a report.

        Args:
            output_path: Where to write the JSON report.
            quick: Use --quick flag for test-simulation-scenarios.sh.
            timeout_s: Wall-clock timeout. Default: quick duration + 60s.
            caldera: If True, use CALDERA for attack orchestration instead
                of calling scenario.setup() directly.
        """
        if timeout_s is None:
            timeout_s = 240 if quick else 3660

        sim_config = {}
        compose_config = {}

        try:
            if caldera:
                from autonomous_trust.evaluation.redteam.caldera_compose import SCENARIO_TO_CALDERA
                caldera_attacks = ','.join(
                    SCENARIO_TO_CALDERA[s.name] for s in self.scenarios
                    if s.name in SCENARIO_TO_CALDERA
                )
                attack_metrics = self._run_simulation(
                    quick=quick, timeout_s=timeout_s,
                    sim_config=sim_config, caldera=True,
                    caldera_attacks=caldera_attacks)
                self._caldera_orchestrate()
            else:
                for scenario in self.scenarios:
                    scenario.setup(sim_config, compose_config)
                attack_metrics = self._run_simulation(
                    quick=quick, timeout_s=timeout_s,
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
                        sim_config: dict, caldera: bool = False,
                        caldera_attacks: str = '') -> dict:
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

        if caldera:
            cmd.extend(['--caldera', '--caldera-attacks', caldera_attacks])
            env = env or os.environ.copy()
            attack_config = {}
            for scenario in self.scenarios:
                if hasattr(scenario, 'num_sybil_nodes'):
                    attack_config['num_sybil_nodes'] = scenario.num_sybil_nodes
                    attack_config['base_ip_offset'] = scenario.base_ip_offset
                if hasattr(scenario, 'byzantine_peer_ids'):
                    attack_config['byzantine_peer_ids'] = scenario.byzantine_peer_ids
                if hasattr(scenario, 'gaming_peer_ids'):
                    attack_config['gaming_peer_ids'] = scenario.gaming_peer_ids
                    attack_config['defection_time_s'] = scenario.defection_time_s
            env['REDTEAM_ATTACK_CONFIG'] = json.dumps(attack_config)

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
            'timestamp': datetime.now(timezone.utc).isoformat(),
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

        # Attack-specific hard invariants. The Sybil scenario reports an
        # explicit distinct-identity bound; an admitted Sybil is a failure
        # regardless of convergence/reputation deltas.
        specific = attack_metrics.get('attack_specific') or {}
        if specific.get('identity_count_bounded') is False:
            return 'FAIL'

        return 'PASS'

    # ------------------------------------------------------------------
    # CALDERA orchestration helpers
    # ------------------------------------------------------------------

    def _caldera_orchestrate(self, caldera_url: str = 'http://10.27.3.2:8888',
                             api_key: str = 'ADMIN123') -> None:
        """Poll for sandcat agents, then launch adversary operations.

        Falls back gracefully if CALDERA is unreachable.
        """
        from autonomous_trust.evaluation.redteam.caldera_compose import (
            SCENARIO_TO_CALDERA,
        )

        agents = self._poll_agents(expected_count=8, timeout_s=120,
                                   caldera_url=caldera_url, api_key=api_key)
        if not agents:
            print('CALDERA: no agents registered, falling back to passive mode',
                  file=sys.stderr)
            return

        for scenario in self.scenarios:
            caldera_name = SCENARIO_TO_CALDERA.get(scenario.name)
            if caldera_name is None:
                continue
            adversary_id = f'at-adversary-{caldera_name}-001'
            op_id = self._start_operation(adversary_id, api_key,
                                          caldera_url=caldera_url)
            if op_id:
                self._wait_operation(op_id, api_key, timeout_s=300,
                                     caldera_url=caldera_url)

    def _poll_agents(self, expected_count: int = 8, timeout_s: int = 120,
                     caldera_url: str = 'http://10.27.3.2:8888',
                     api_key: str = 'ADMIN123') -> list:
        """Poll CALDERA /api/v2/agents until *expected_count* register.

        Returns the list of agent dicts, or [] on timeout / error.
        """
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            try:
                req = urllib.request.Request(
                    f'{caldera_url}/api/v2/agents',
                    headers={'KEY': api_key},
                )
                with urllib.request.urlopen(req, timeout=5) as resp:
                    agents = json.loads(resp.read())
                if len(agents) >= expected_count:
                    return agents
            except Exception:
                pass
            time.sleep(2)
        return []

    def _start_operation(self, adversary_id: str, api_key: str,
                         caldera_url: str = 'http://10.27.3.2:8888') -> Optional[str]:
        """POST to /api/v2/operations to kick off an adversary.

        Returns the operation id, or None on failure.
        """
        payload = json.dumps({
            'name': f'redteam-{adversary_id}',
            'adversary': {'adversary_id': adversary_id},
            'planner': {'id': 'atomic'},
            'source': {'id': 'basic'},
            'auto_close': True,
        }).encode()
        req = urllib.request.Request(
            f'{caldera_url}/api/v2/operations',
            data=payload,
            headers={'KEY': api_key, 'Content-Type': 'application/json'},
            method='POST',
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                body = json.loads(resp.read())
            return body.get('id')
        except Exception as exc:
            print(f'CALDERA: failed to start operation {adversary_id}: {exc}',
                  file=sys.stderr)
            return None

    def _wait_operation(self, op_id: str, api_key: str,
                        timeout_s: int = 300,
                        caldera_url: str = 'http://10.27.3.2:8888') -> None:
        """Poll operation status until it reaches 'finished' or timeout."""
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            try:
                req = urllib.request.Request(
                    f'{caldera_url}/api/v2/operations/{op_id}',
                    headers={'KEY': api_key},
                )
                with urllib.request.urlopen(req, timeout=5) as resp:
                    body = json.loads(resp.read())
                if body.get('state') == 'finished':
                    return
            except Exception:
                pass
            time.sleep(3)
