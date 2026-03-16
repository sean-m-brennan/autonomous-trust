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
