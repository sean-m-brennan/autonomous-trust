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

"""Tests for asteroid belt scenario configuration (Phase 5)."""

from __future__ import annotations

import math

import pytest

try:
    from examples.asteroid_belt.scenario import (
        create_asteroid_belt_config, HABITATS, SUN_POSITION,
    )
    from autonomous_trust.simulator.sim_data import SimConfig
    from autonomous_trust.simulator.radio.space_link import AU_M
    from autonomous_trust.simulator.radio.iface import NetInterface
except ImportError as _e:
    pytestmark = pytest.mark.skip(reason=f"missing dependency: {_e}")


class TestAsteroidBeltScenario:
    """Verify the asteroid belt scenario generates valid config."""

    @pytest.fixture
    def config_path(self, tmp_path):
        return create_asteroid_belt_config(output_file=str(tmp_path / 'belt.cfg'))

    @pytest.fixture
    def config(self, config_path):
        with open(config_path, 'r') as f:
            return SimConfig.load(f.read())

    def test_creates_config_file(self, config_path):
        import os
        assert os.path.exists(config_path)

    def test_space_mode_enabled(self, config):
        assert config.space_mode is True

    def test_has_sun_position(self, config):
        assert config.sun_position is not None

    def test_has_comm_freq(self, config):
        assert config.comm_freq_hz is not None
        assert config.comm_freq_hz > 0

    def test_correct_peer_count(self, config):
        """Should have same number of peers as HABITATS."""
        assert len(config.peers) == len(HABITATS)

    def test_all_peers_have_space_interfaces(self, config):
        """All peers use LASER_COMMS or DEEP_SPACE."""
        space_ifaces = {NetInterface.LASER_COMMS, NetInterface.DEEP_SPACE}
        for peer in config.peers:
            assert peer.iface in space_ifaces, f"{peer.nickname} has non-space iface {peer.iface}"

    def test_orbits_are_belt_scale(self, config):
        """Orbital semi-major axes should be in the 2-4 AU range."""
        for peer in config.peers:
            for path_data in peer.path_list:
                shape = path_data.shape
                # EllipseData semi_major should be 2-4 AU
                semi_major_au = shape.semi_major / AU_M
                assert 1.5 < semi_major_au < 5.0, \
                    f"{peer.nickname} orbit {semi_major_au:.2f} AU outside belt range"

    def test_habitats_have_distinct_orbits(self, config):
        """No two habitats should have identical orbital parameters."""
        seen = set()
        for peer in config.peers:
            shape = peer.path_list[0].shape
            key = (shape.semi_major, shape.semi_minor, shape.angle)
            assert key not in seen, f"Duplicate orbit for {peer.nickname}"
            seen.add(key)


class TestHabitatDefinitions:
    """Verify HABITATS list is well-formed."""

    def test_at_least_five_habitats(self):
        assert len(HABITATS) >= 5

    def test_at_most_ten_habitats(self):
        assert len(HABITATS) <= 10

    def test_all_have_required_fields(self):
        for h in HABITATS:
            assert 'name' in h
            assert 'semi_major_au' in h
            assert 'eccentricity' in h
            assert 'angle_deg' in h
