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

"""Tests for space-mode simulation support (Phase 5)."""

from __future__ import annotations

import math
from datetime import datetime, timedelta

import pytest

try:
    from autonomous_trust.services.peer.position import UTMPosition
    from autonomous_trust.simulator.sim_data import (
        SimConfig, SimState, DelayMatrix, SignalMatrix,
    )
    from autonomous_trust.simulator.radio.space_link import AU_M, C_M_S, light_delay_s
    from autonomous_trust.simulator.radio.iface import NetInterface, Antenna
    from autonomous_trust.simulator.peer.path import EllipseData, PathData, Variability
    from autonomous_trust.simulator.peer.peer import PeerInfo, PeerConnection
    from autonomous_trust.simulator.simulator import Simulator
except ImportError as _e:
    pytestmark = pytest.mark.skip(reason=f"missing dependency: {_e}")


DUMMY_ZONE = '1N'
SUN_POS = UTMPosition(DUMMY_ZONE, 0.0, 0.0, 0.0)


class TestSimConfigSpaceMode:
    """SimConfig accepts space-mode parameters."""

    def test_space_mode_default_false(self):
        start = datetime.now()
        cfg = SimConfig(start=start, end=start + timedelta(hours=1), peers=[])
        assert cfg.space_mode is False

    def test_space_mode_set(self):
        start = datetime.now()
        cfg = SimConfig(
            start=start, end=start + timedelta(hours=1), peers=[],
            space_mode=True, comm_freq_hz=8.4e9,
            sun_position=SUN_POS,
        )
        assert cfg.space_mode is True
        assert cfg.comm_freq_hz == 8.4e9
        assert cfg.sun_position is SUN_POS


class TestSimStateDelay:
    """SimState carries delay matrix."""

    def test_delay_default_empty(self):
        state = SimState()
        assert state.delay == {}

    def test_delay_set(self):
        delays: DelayMatrix = {'a': {'b': 1000.0}}
        state = SimState(delay=delays)
        assert state.delay['a']['b'] == 1000.0


class TestSpaceModeComputeStep:
    """Simulator.compute_step in space mode computes FSPL, LOS, and delays."""

    @pytest.fixture
    def space_config_file(self, tmp_path):
        """Create a minimal space-mode SimConfig with 2 habitats on circular orbits."""
        start = datetime(2026, 1, 1)
        end = start + timedelta(days=365)

        # Habitat A: circular orbit at 2.2 AU
        a_semi = 2.2 * AU_M
        a_pos = UTMPosition(DUMMY_ZONE, a_semi, 0.0, 0.0)  # start on +x axis
        a_shape = EllipseData(SUN_POS, a_semi, a_semi, 0.0, 1)
        a_path = PathData(start, end, a_shape, Variability.UNIFORM, 0, Variability.UNIFORM)

        # Habitat B: circular orbit at 3.1 AU, 90 degrees ahead
        b_semi = 3.1 * AU_M
        b_pos = UTMPosition(DUMMY_ZONE, 0.0, b_semi, 0.0)  # start on +y axis
        b_shape = EllipseData(SUN_POS, b_semi, b_semi, 90.0, 1)
        b_path = PathData(start, end, b_shape, Variability.UNIFORM, 0, Variability.UNIFORM)

        peers = [
            PeerInfo(
                uuid='habitat-a', kind='habitat', nickname='alpha',
                ip4_addr='10.0.0.1', initial_position=a_pos,
                signal=40.0, antenna=Antenna.LASER,
                iface=NetInterface.LASER_COMMS,
                initial_time=start, last_seen=end,
                path_list=[a_path], data_streams=[],
            ),
            PeerInfo(
                uuid='habitat-b', kind='habitat', nickname='beta',
                ip4_addr='10.0.0.2', initial_position=b_pos,
                signal=40.0, antenna=Antenna.HIGH_GAIN_PARABOLIC,
                iface=NetInterface.DEEP_SPACE,
                initial_time=start, last_seen=end,
                path_list=[b_path], data_streams=[],
            ),
        ]

        cfg = SimConfig(
            start=start, end=end, peers=peers,
            space_mode=True, comm_freq_hz=8.4e9,
            sun_position=SUN_POS,
        )
        cfg_path = str(tmp_path / 'space_test.cfg')
        cfg.to_file(cfg_path)
        return cfg_path

    def test_compute_step_returns_delay(self, space_config_file):
        """compute_step in space mode populates delay values."""
        sim = Simulator(space_config_file, max_time_steps=10, precompute=False)
        # tick 0 returns None positions (PeerMovement offset=1); use tick 1
        result = sim.compute_step(1)
        # Result tuple: (center, max_dist, mapp, matrix, active, sig_quality, delay)
        assert len(result) == 7
        delay = result[6]
        assert 'habitat-a' in delay
        assert 'habitat-b' in delay['habitat-a']
        # Delay should be positive (habitats are separated)
        assert delay['habitat-a']['habitat-b'] > 0

    def test_delay_consistent_with_distance(self, space_config_file):
        """Delay = distance / c for each pair."""
        sim = Simulator(space_config_file, max_time_steps=10, precompute=False)
        # tick 0 returns None positions (PeerMovement offset=1); use tick 1
        center, max_dist, mapp, matrix, active, sig_quality, delay = sim.compute_step(1)
        # Compute expected delay from positions
        pos_a = mapp['habitat-a'].position
        pos_b = mapp['habitat-b'].position
        dist = pos_a.distance(pos_b)
        expected_delay = light_delay_s(dist)
        actual_delay = delay['habitat-a']['habitat-b']
        assert abs(actual_delay - expected_delay) / expected_delay < 0.01  # 1% tolerance

    def test_space_mode_computes_fspl(self, space_config_file):
        """In space mode, sig_quality contains FSPL values (not terrain loss)."""
        sim = Simulator(space_config_file, max_time_steps=10, precompute=False)
        # tick 0 returns None positions (PeerMovement offset=1); use tick 1
        center, max_dist, mapp, matrix, active, sig_quality, delay = sim.compute_step(1)
        # FSPL should be present and very large for AU-scale distances
        assert 'habitat-a' in sig_quality
        loss = sig_quality['habitat-a']['habitat-b']
        assert loss > 200  # AU-scale FSPL at GHz is > 200 dB
