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
"""Tests for RedTeamHarness CALDERA mode."""

import json
import pytest
from unittest.mock import patch, MagicMock, call

from autonomous_trust.simulator.redteam.harness import RedTeamHarness
from autonomous_trust.simulator.redteam.sybil_attack import SybilAttack
from autonomous_trust.simulator.redteam.byzantine_node import ByzantineNodeAttack


class TestCalderaFlag:

    def test_caldera_false_calls_setup(self, tmp_path):
        baseline = tmp_path / 'baseline.json'
        baseline.write_text(json.dumps({'identity_convergence_s': 74}))

        scenario = MagicMock()
        scenario.name = 'sybil_attack'
        scenario.description = 'test'
        scenario.collect.return_value = {'attack_specific': {}}

        harness = RedTeamHarness(str(baseline), [scenario])
        with patch.object(harness, '_run_simulation', return_value={}):
            harness.run(str(tmp_path / 'out.json'), caldera=False)

        scenario.setup.assert_called_once()

    def test_caldera_true_skips_setup(self, tmp_path):
        baseline = tmp_path / 'baseline.json'
        baseline.write_text(json.dumps({'identity_convergence_s': 74}))

        scenario = MagicMock()
        scenario.name = 'sybil_attack'
        scenario.description = 'test'
        scenario.collect.return_value = {'attack_specific': {}}

        harness = RedTeamHarness(str(baseline), [scenario])
        with patch.object(harness, '_run_simulation', return_value={}) as mock_sim, \
             patch.object(harness, '_caldera_orchestrate'):
            harness.run(str(tmp_path / 'out.json'), caldera=True)

        scenario.setup.assert_not_called()

    def test_caldera_derives_attack_names(self, tmp_path):
        baseline = tmp_path / 'baseline.json'
        baseline.write_text(json.dumps({'identity_convergence_s': 74}))

        sybil = SybilAttack(num_sybil_nodes=2)
        byzantine = ByzantineNodeAttack(byzantine_peer_ids=['p1'])
        harness = RedTeamHarness(str(baseline), [sybil, byzantine])

        with patch.object(harness, '_run_simulation', return_value={}) as mock_sim, \
             patch.object(harness, '_caldera_orchestrate'):
            harness.run(str(tmp_path / 'out.json'), caldera=True)

        _, kwargs = mock_sim.call_args
        assert kwargs.get('caldera') is True
        attacks = kwargs.get('caldera_attacks', '')
        assert 'sybil' in attacks
        assert 'byzantine' in attacks


class TestCalderaOperations:

    def test_start_operation_sends_post(self, tmp_path):
        baseline = tmp_path / 'baseline.json'
        baseline.write_text(json.dumps({'identity_convergence_s': 74}))
        harness = RedTeamHarness(str(baseline), [])

        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({'id': 'op-123'}).encode()
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch('urllib.request.urlopen', return_value=mock_response) as mock_open:
            op_id = harness._start_operation('at-adversary-sybil-001', 'ADMIN123')

        assert op_id == 'op-123'
        req = mock_open.call_args[0][0]
        assert req.method == 'POST'
        body = json.loads(req.data)
        assert body['adversary']['adversary_id'] == 'at-adversary-sybil-001'

    def test_wait_operation_returns_on_finished(self, tmp_path):
        baseline = tmp_path / 'baseline.json'
        baseline.write_text(json.dumps({'identity_convergence_s': 74}))
        harness = RedTeamHarness(str(baseline), [])

        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({'state': 'finished'}).encode()
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch('urllib.request.urlopen', return_value=mock_response):
            harness._wait_operation('op-123', 'ADMIN123', timeout_s=5)


class TestCalderaOrchestrate:

    def test_polls_agents_endpoint(self, tmp_path):
        baseline = tmp_path / 'baseline.json'
        baseline.write_text(json.dumps({'identity_convergence_s': 74}))

        harness = RedTeamHarness(str(baseline), [])

        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps([
            {'paw': 'abc', 'group': 'node1'}
        ]).encode()
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch('urllib.request.urlopen', return_value=mock_response):
            agents = harness._poll_agents(expected_count=1, timeout_s=5)

        assert len(agents) == 1


class TestCalderaFallback:

    def test_agent_timeout_falls_back(self, tmp_path):
        baseline = tmp_path / 'baseline.json'
        baseline.write_text(json.dumps({'identity_convergence_s': 74}))

        harness = RedTeamHarness(str(baseline), [])

        with patch('urllib.request.urlopen', side_effect=Exception('connection refused')):
            agents = harness._poll_agents(expected_count=8, timeout_s=1)

        assert agents == []
