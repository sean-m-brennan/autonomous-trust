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
"""Tests for ByzantineReputationProcess."""

import pytest
from unittest.mock import MagicMock
from uuid import uuid4

from autonomous_trust.simulator.redteam.byzantine_node import (
    ByzantineNodeAttack,
)
from autonomous_trust.simulator.redteam import AttackScenario


class TestByzantineNodeAttack:
    """ByzantineNodeAttack scenario tests."""

    def test_is_attack_scenario(self):
        attack = ByzantineNodeAttack(byzantine_peer_ids=["peer_1"])
        assert isinstance(attack, AttackScenario)
        assert attack.name == "byzantine_node"

    def test_setup_modifies_config(self):
        attack = ByzantineNodeAttack(byzantine_peer_ids=["peer_1"])
        sim_config = {}
        compose_config = {}
        attack.setup(sim_config, compose_config)
        assert 'byzantine_peers' in sim_config
        assert sim_config['byzantine_peers'] == ["peer_1"]

    def test_collect_adds_attack_metrics(self):
        attack = ByzantineNodeAttack(byzantine_peer_ids=["peer_1", "peer_2"])
        result = attack.collect({})
        assert result['attack_specific']['byzantine_peer_ids'] == ["peer_1", "peer_2"]
        assert 'byzantine_detected' in result['attack_specific']
        assert 'consensus_integrity' in result['attack_specific']


from autonomous_trust.simulator.redteam.reputation_gaming import ReputationGamingAttack


class TestReputationGamingAttack:
    def test_is_attack_scenario(self):
        attack = ReputationGamingAttack(
            gaming_peer_ids=["peer_1"],
            defection_time_s=60.0,
        )
        assert attack.name == "reputation_gaming"

    def test_setup_sets_defection_time(self):
        attack = ReputationGamingAttack(
            gaming_peer_ids=["peer_1"],
            defection_time_s=60.0,
        )
        sim_config = {}
        attack.setup(sim_config, {})
        assert sim_config['gaming_peers'] == ["peer_1"]
        assert sim_config['defection_time_s'] == 60.0
