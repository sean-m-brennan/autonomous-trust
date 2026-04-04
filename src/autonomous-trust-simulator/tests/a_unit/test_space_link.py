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

"""Tests for space link physics calculations (Phase 5)."""

from __future__ import annotations

import math

import pytest

try:
    from autonomous_trust.services.peer.position import UTMPosition
    from autonomous_trust.simulator.radio.space_link import (
        C_M_S, AU_M, SUN_RADIUS_M,
        light_delay_s, free_space_path_loss_db, sun_occluded,
    )
except ImportError as _e:
    pytestmark = pytest.mark.skip(reason=f"missing dependency: {_e}")


DUMMY_ZONE = '1N'


class TestLightDelay:
    """Verify light delay = distance / c."""

    def test_one_au(self):
        delay = light_delay_s(AU_M)
        # 1 AU light time is ~499.0 seconds
        assert abs(delay - 499.0) < 0.5

    def test_zero_distance(self):
        assert light_delay_s(0.0) == 0.0

    def test_two_point_three_au(self):
        """Worked example from system-simulation.md: 2.31 AU -> ~1152.7s."""
        delay = light_delay_s(2.31 * AU_M)
        assert abs(delay - 1152.7) < 1.0

    def test_proportional(self):
        d1 = light_delay_s(1.0 * AU_M)
        d2 = light_delay_s(2.0 * AU_M)
        assert abs(d2 / d1 - 2.0) < 1e-10


class TestFreeSpacePathLoss:
    """Verify FSPL formula: 20*log10(d) + 20*log10(f) + 20*log10(4*pi/c)."""

    def test_known_value_1km_1ghz(self):
        """FSPL at 1 km, 1 GHz should be ~92.4 dB."""
        loss = free_space_path_loss_db(1000.0, 1.0e9)
        assert abs(loss - 92.4) < 0.2

    def test_known_value_10km_5ghz(self):
        """FSPL at 10 km, 5.8 GHz should be ~127.7 dB."""
        loss = free_space_path_loss_db(10_000.0, 5.8e9)
        assert abs(loss - 127.7) < 0.5

    def test_inverse_square_scaling(self):
        """Doubling distance adds ~6 dB."""
        loss1 = free_space_path_loss_db(AU_M, 8.4e9)
        loss2 = free_space_path_loss_db(2 * AU_M, 8.4e9)
        assert abs((loss2 - loss1) - 6.02) < 0.1

    def test_zero_distance_returns_zero(self):
        assert free_space_path_loss_db(0.0, 1e9) == 0.0

    def test_zero_freq_returns_zero(self):
        assert free_space_path_loss_db(1000.0, 0.0) == 0.0


class TestSunOccultation:
    """Verify line-of-sight check against the Sun's sphere."""

    @pytest.fixture
    def sun(self):
        """Sun at origin of coordinate frame."""
        return UTMPosition(DUMMY_ZONE, 0.0, 0.0, 0.0)

    def test_direct_through_sun(self, sun):
        """Two habitats on opposite sides of sun — occluded."""
        a = UTMPosition(DUMMY_ZONE, -2 * AU_M, 0.0, 0.0)
        b = UTMPosition(DUMMY_ZONE, 2 * AU_M, 0.0, 0.0)
        assert sun_occluded(a, b, sun) is True

    def test_well_clear(self, sun):
        """Two habitats at 90 degrees — no occultation."""
        a = UTMPosition(DUMMY_ZONE, 2 * AU_M, 0.0, 0.0)
        b = UTMPosition(DUMMY_ZONE, 0.0, 2 * AU_M, 0.0)
        assert sun_occluded(a, b, sun) is False

    def test_grazing_miss(self, sun):
        """Line segment just misses the Sun's edge."""
        offset = SUN_RADIUS_M * 1.5  # 50% beyond edge
        a = UTMPosition(DUMMY_ZONE, -2 * AU_M, offset, 0.0)
        b = UTMPosition(DUMMY_ZONE, 2 * AU_M, offset, 0.0)
        assert sun_occluded(a, b, sun) is False

    def test_grazing_hit(self, sun):
        """Line segment just clips the Sun's edge."""
        offset = SUN_RADIUS_M * 0.5  # inside the radius
        a = UTMPosition(DUMMY_ZONE, -2 * AU_M, offset, 0.0)
        b = UTMPosition(DUMMY_ZONE, 2 * AU_M, offset, 0.0)
        assert sun_occluded(a, b, sun) is True

    def test_same_side_of_sun(self, sun):
        """Both habitats on same side — never occluded even if near sun."""
        a = UTMPosition(DUMMY_ZONE, 2 * AU_M, 0.0, 0.0)
        b = UTMPosition(DUMMY_ZONE, 2.5 * AU_M, 0.1 * AU_M, 0.0)
        assert sun_occluded(a, b, sun) is False

    def test_custom_radius(self, sun):
        """Use oversized radius for exclusion zone."""
        a = UTMPosition(DUMMY_ZONE, -2 * AU_M, 0.0, 0.0)
        b = UTMPosition(DUMMY_ZONE, 2 * AU_M, 5e9, 0.0)  # offset
        # Default sun radius: line is clear
        assert sun_occluded(a, b, sun) is False
        # With 10x radius: line is blocked
        assert sun_occluded(a, b, sun, sun_radius_m=SUN_RADIUS_M * 20) is True
