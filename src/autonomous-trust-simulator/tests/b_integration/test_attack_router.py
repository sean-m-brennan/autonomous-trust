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
"""Tests for AttackRouter partition scheduling."""

import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta

from autonomous_trust.simulator.redteam import PartitionEvent
from autonomous_trust.simulator.redteam.attack_router import AttackRouter, NetworkPartitionAttack


class TestPartitionSchedule:
    """AttackRouter activates/deactivates partitions based on elapsed time."""

    def test_no_partitions_no_activation(self):
        """With empty partition list, _apply_partitions is a no-op."""
        router = AttackRouter.__new__(AttackRouter)
        router.partitions = []
        router._active_partitions = set()
        router._start_time = None

        state = MagicMock()
        state.time = datetime(2026, 1, 1, 0, 0, 10)
        router._apply_partitions(state)
        assert router._active_partitions == set()

    def test_partition_activates_at_start_time(self):
        """Partition becomes active when elapsed >= start_s."""
        event = PartitionEvent(
            start_s=10.0, end_s=30.0,
            group_a=["peer_a"], group_b=["peer_b"]
        )
        router = AttackRouter.__new__(AttackRouter)
        router.partitions = [event]
        router._active_partitions = set()
        router._start_time = datetime(2026, 1, 1, 0, 0, 0)
        router.containerized = False
        router.all_peers = []

        state = MagicMock()
        state.time = datetime(2026, 1, 1, 0, 0, 15)
        state.reachable = {}
        state.peers = {
            "peer_a": MagicMock(ip4_addr="10.27.3.11"),
            "peer_b": MagicMock(ip4_addr="10.27.3.12"),
        }

        with patch.object(AttackRouter, '_activate_partition') as mock_activate:
            router._apply_partitions(state)
            mock_activate.assert_called_once_with(event, state)
        assert 0 in router._active_partitions

    def test_partition_deactivates_after_end_time(self):
        """Partition is removed when elapsed >= end_s."""
        event = PartitionEvent(
            start_s=10.0, end_s=30.0,
            group_a=["peer_a"], group_b=["peer_b"]
        )
        router = AttackRouter.__new__(AttackRouter)
        router.partitions = [event]
        router._active_partitions = {0}
        router._start_time = datetime(2026, 1, 1, 0, 0, 0)
        router.containerized = False

        state = MagicMock()
        state.time = datetime(2026, 1, 1, 0, 0, 35)
        state.peers = {
            "peer_a": MagicMock(ip4_addr="10.27.3.11"),
            "peer_b": MagicMock(ip4_addr="10.27.3.12"),
        }

        with patch.object(AttackRouter, '_deactivate_partition') as mock_deactivate:
            router._apply_partitions(state)
            mock_deactivate.assert_called_once_with(event, state)
        assert 0 not in router._active_partitions


class TestPartitionIptables:
    """AttackRouter injects correct iptables DROP rules for partitions."""

    def test_activate_drops_bidirectional(self):
        """Activating a partition adds DROP rules in both directions."""
        event = PartitionEvent(
            start_s=0, end_s=60,
            group_a=["peer_a"], group_b=["peer_b"]
        )
        router = AttackRouter.__new__(AttackRouter)
        router.containerized = False

        state = MagicMock()
        state.peers = {
            "peer_a": MagicMock(ip4_addr="10.27.3.11"),
            "peer_b": MagicMock(ip4_addr="10.27.3.12"),
        }

        with patch.object(AttackRouter, 'iptables') as mock_ipt:
            router._activate_partition(event, state)
            calls = [str(c) for c in mock_ipt.call_args_list]
            assert any('-s 10.27.3.11 -d 10.27.3.12 -j DROP' in c for c in calls)
            assert any('-s 10.27.3.12 -d 10.27.3.11 -j DROP' in c for c in calls)

    def test_deactivate_removes_drops(self):
        """Deactivating a partition removes the DROP rules."""
        event = PartitionEvent(
            start_s=0, end_s=60,
            group_a=["peer_a"], group_b=["peer_b"]
        )
        router = AttackRouter.__new__(AttackRouter)
        router.containerized = False

        state = MagicMock()
        state.peers = {
            "peer_a": MagicMock(ip4_addr="10.27.3.11"),
            "peer_b": MagicMock(ip4_addr="10.27.3.12"),
        }

        with patch.object(AttackRouter, 'iptables') as mock_ipt:
            router._deactivate_partition(event, state)
            calls = [str(c) for c in mock_ipt.call_args_list]
            assert any('-D' in c and '10.27.3.11' in c and '10.27.3.12' in c for c in calls)
            assert any('-D' in c and '10.27.3.12' in c and '10.27.3.11' in c for c in calls)


class TestNetworkPartitionAttack:
    """NetworkPartitionAttack is a proper AttackScenario."""

    def test_setup_configures_router(self):
        event = PartitionEvent(start_s=0, end_s=60, group_a=["a"], group_b=["b"])
        attack = NetworkPartitionAttack(partitions=[event])
        sim_config = {}
        attack.setup(sim_config, {})
        assert sim_config['router_class'] == AttackRouter
        assert sim_config['router_kwargs']['partitions'] == [event]

    def test_collect_adds_partition_metadata(self):
        event = PartitionEvent(start_s=10, end_s=50, group_a=["a"], group_b=["b"])
        attack = NetworkPartitionAttack(partitions=[event])
        result = attack.collect({})
        assert result['attack_specific']['partitions_scheduled'] == 1
