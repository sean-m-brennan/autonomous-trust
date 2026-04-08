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
"""Tests for the red team harness orchestrator."""

import json
import os
import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime

from autonomous_trust.evaluation.redteam import AttackScenario, PartitionEvent
from autonomous_trust.evaluation.redteam.harness import RedTeamHarness


class FakeAttack(AttackScenario):
    name = "fake_attack"
    description = "Test attack"

    def __init__(self):
        self.setup_called = False
        self.teardown_called = False
        self.collect_called = False

    def setup(self, sim_config, compose_config):
        self.setup_called = True

    def teardown(self):
        self.teardown_called = True

    def collect(self, metrics):
        self.collect_called = True
        metrics['attack_specific'] = {'fake_metric': 42}
        return metrics


class TestHarnessReportGeneration:
    """Harness produces correct JSON report structure."""

    def test_report_structure(self, tmp_path):
        """Report contains baseline, attacks array, and summary."""
        baseline = {
            'identity_convergence_s': 74.1,
            'reputation_stability_stddev': 0.0,
            'negotiation_rtt_mean_s': 76.4,
            'bandwidth_overhead_fraction': 0.118,
        }
        baseline_file = tmp_path / 'baseline.json'
        baseline_file.write_text(json.dumps(baseline))

        harness = RedTeamHarness(
            baseline_path=str(baseline_file),
            scenarios=[FakeAttack()],
        )
        report = harness.build_report(
            attack_metrics={'identity_convergence_s': 80.0},
        )
        assert 'timestamp' in report
        assert report['baseline'] == baseline
        assert len(report['attacks']) == 1
        assert report['attacks'][0]['name'] == 'fake_attack'
        assert report['attacks'][0]['attack_specific']['fake_metric'] == 42
        assert 'summary' in report

    def test_teardown_called_on_error(self, tmp_path):
        """Teardown is always called even if simulation fails."""
        baseline_file = tmp_path / 'baseline.json'
        baseline_file.write_text('{}')

        attack = FakeAttack()
        harness = RedTeamHarness(
            baseline_path=str(baseline_file),
            scenarios=[attack],
        )
        with patch.object(harness, '_run_simulation', side_effect=RuntimeError("boom")):
            with pytest.raises(RuntimeError):
                harness.run(output_path=str(tmp_path / 'out.json'), quick=True)
        assert attack.teardown_called

    def test_pass_fail_assessment(self, tmp_path):
        """Report marks attacks as PASS/FAIL/ERROR based on metrics."""
        baseline_file = tmp_path / 'baseline.json'
        baseline_file.write_text(json.dumps({
            'identity_convergence_s': 74.1,
            'reputation_stability_stddev': 0.0,
        }))

        harness = RedTeamHarness(
            baseline_path=str(baseline_file),
            scenarios=[FakeAttack()],
        )
        report = harness.build_report(
            attack_metrics={'identity_convergence_s': 200.0},
        )
        assert report['attacks'][0]['result'] in ('PASS', 'FAIL', 'ERROR', 'NO_DATA')

    def test_error_on_no_metrics(self, tmp_path):
        baseline_file = tmp_path / 'baseline.json'
        baseline_file.write_text('{}')
        harness = RedTeamHarness(baseline_path=str(baseline_file), scenarios=[FakeAttack()])
        report = harness.build_report(attack_metrics={'error': 'no_metrics'})
        assert report['attacks'][0]['result'] == 'NO_DATA'

    def test_error_on_timeout(self, tmp_path):
        baseline_file = tmp_path / 'baseline.json'
        baseline_file.write_text('{}')
        harness = RedTeamHarness(baseline_path=str(baseline_file), scenarios=[FakeAttack()])
        report = harness.build_report(attack_metrics={'error': 'timeout'})
        assert report['attacks'][0]['result'] == 'ERROR'


from autonomous_trust.evaluation.redteam.sybil_attack import SybilAttack


class TestSybilAttackSetup:
    def test_adds_sybil_containers(self):
        attack = SybilAttack(num_sybil_nodes=3, base_ip_offset=30)
        sim_config = {}
        compose_config = {'services': {}, 'networks': {'at-net': {}}}
        attack.setup(sim_config, compose_config)
        sybil_services = [k for k in compose_config['services'] if k.startswith('sybil-')]
        assert len(sybil_services) == 3

    def test_sybil_containers_on_same_network(self):
        attack = SybilAttack(num_sybil_nodes=2, base_ip_offset=30)
        sim_config = {}
        compose_config = {'services': {}, 'networks': {'at-net': {'ipam': {'config': [{'subnet': '10.27.3.0/24'}]}}}}
        attack.setup(sim_config, compose_config)
        for name, svc in compose_config['services'].items():
            if name.startswith('sybil-'):
                assert 'at-net' in svc.get('networks', {})


from autonomous_trust.evaluation.redteam.mitm_attack import MitmAttack


class TestMitmAttackSetup:
    def test_adds_tcpdump_sidecar(self):
        attack = MitmAttack(target_peer_a="peer_a", target_peer_b="peer_b")
        sim_config = {}
        compose_config = {'services': {}}
        attack.setup(sim_config, compose_config)
        assert 'tcpdump-mitm' in compose_config['services']

    def test_collect_reports_encryption_status(self):
        attack = MitmAttack(target_peer_a="peer_a", target_peer_b="peer_b")
        result = attack.collect({})
        assert 'plaintext_extracted' in result['attack_specific']
        assert 'replay_accepted' in result['attack_specific']

    def test_collect_detects_plaintext_in_pcap(self, tmp_path):
        pcap_file = tmp_path / 'test.pcap'
        pcap_file.write_bytes(b'header\x00ask permission\x00more data')
        attack = MitmAttack(target_peer_a="a", target_peer_b="b",
                          pcap_path=str(pcap_file))
        result = attack.collect({})
        assert result['attack_specific']['plaintext_extracted'] is True
        assert 'ask permission' in result['attack_specific']['signatures_found']


from autonomous_trust.evaluation.redteam.report import generate_markdown_report


class TestMarkdownReport:
    def test_generates_markdown_from_json_report(self):
        report = {
            'timestamp': '2026-03-16T12:00:00',
            'baseline': {'identity_convergence_s': 74.1},
            'attacks': [
                {
                    'name': 'network_partition',
                    'description': 'iptables split',
                    'metrics_during_attack': {'identity_convergence_s': 120.0},
                    'attack_specific': {'partitions_scheduled': 1},
                    'result': 'PASS',
                },
            ],
            'summary': {'total': 1, 'passed': 1, 'failed': 0, 'errors': 0},
        }
        md = generate_markdown_report(report)
        assert '# Red Team Report' in md
        assert 'network_partition' in md
        assert 'PASS' in md
        assert '74.1' in md
