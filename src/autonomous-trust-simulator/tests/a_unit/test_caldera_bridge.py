"""Tests for caldera_bridge CLI dispatcher."""

import json
import pytest
from unittest.mock import patch, MagicMock

from autonomous_trust.simulator.redteam.caldera_bridge import (
    ATTACK_MAP, dispatch_collect, main,
)


class TestAttackMap:
    """ATTACK_MAP maps string names to AttackScenario classes."""

    def test_sybil_maps_to_sybil_attack(self):
        from autonomous_trust.simulator.redteam.sybil_attack import SybilAttack
        assert ATTACK_MAP['sybil'] is SybilAttack

    def test_byzantine_maps_to_byzantine_node_attack(self):
        from autonomous_trust.simulator.redteam.byzantine_node import ByzantineNodeAttack
        assert ATTACK_MAP['byzantine'] is ByzantineNodeAttack

    def test_reputation_gaming_maps_to_gaming_attack(self):
        from autonomous_trust.simulator.redteam.reputation_gaming import ReputationGamingAttack
        assert ATTACK_MAP['reputation_gaming'] is ReputationGamingAttack


class TestDispatchCollect:
    """dispatch_collect instantiates scenario and calls collect()."""

    def test_returns_json_dict(self):
        result = dispatch_collect('sybil', {'num_sybil_nodes': 3})
        assert 'attack_specific' in result
        assert result['attack_specific']['sybil_identities_attempted'] == 3

    def test_unknown_attack_raises_key_error(self):
        with pytest.raises(KeyError):
            dispatch_collect('nonexistent', {})

    def test_byzantine_with_peer_ids(self):
        result = dispatch_collect('byzantine', {'byzantine_peer_ids': ['p1']})
        assert result['attack_specific']['byzantine_peer_ids'] == ['p1']


class TestMain:
    """main() parses args, reads config JSON, dispatches, prints JSON."""

    def test_main_prints_json_to_stdout(self, tmp_path, capsys):
        config_file = tmp_path / 'config.json'
        config_file.write_text(json.dumps({'num_sybil_nodes': 2}))

        with patch('sys.argv', ['caldera_bridge',
                                '--attack', 'sybil',
                                '--action', 'collect',
                                '--config', str(config_file)]):
            main()

        output = json.loads(capsys.readouterr().out)
        assert output['attack_specific']['sybil_identities_attempted'] == 2

    def test_main_exits_1_on_unknown_attack(self, tmp_path):
        config_file = tmp_path / 'config.json'
        config_file.write_text('{}')

        with patch('sys.argv', ['caldera_bridge',
                                '--attack', 'bad',
                                '--action', 'collect',
                                '--config', str(config_file)]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 1

    def test_main_exits_1_on_missing_config(self, tmp_path):
        with patch('sys.argv', ['caldera_bridge',
                                '--attack', 'sybil',
                                '--action', 'collect',
                                '--config', str(tmp_path / 'nonexistent.json')]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 1

    def test_main_exits_1_on_malformed_json(self, tmp_path):
        config_file = tmp_path / 'bad.json'
        config_file.write_text('not valid json{{{')

        with patch('sys.argv', ['caldera_bridge',
                                '--attack', 'sybil',
                                '--action', 'collect',
                                '--config', str(config_file)]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 1
