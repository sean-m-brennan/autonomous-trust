# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
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

"""Tests for space communication interface types (Phase 5)."""

from __future__ import annotations

import pytest

try:
    from autonomous_trust.simulator.radio.iface import NetInterface, Antenna
    from autonomous_trust.simulator.peer.peer import PeerConnection
except ImportError as _e:
    pytestmark = pytest.mark.skip(reason=f"missing dependency: {_e}")


class TestSpaceNetInterfaces:
    """Verify LASER_COMMS and DEEP_SPACE interface types."""

    def test_laser_comms_exists(self):
        iface = NetInterface.LASER_COMMS
        assert iface.value == 'laser_comms'

    def test_deep_space_exists(self):
        iface = NetInterface.DEEP_SPACE
        assert iface.value == 'deep_space'

    def test_laser_comms_rate(self):
        assert NetInterface.LASER_COMMS.rate == 10_000_000  # 10 Mbps

    def test_deep_space_rate(self):
        assert NetInterface.DEEP_SPACE.rate == 100_000  # 100 Kbps

    def test_laser_comms_mark(self):
        assert NetInterface.LASER_COMMS.mark == 44

    def test_deep_space_mark(self):
        assert NetInterface.DEEP_SPACE.mark == 55

    def test_existing_interfaces_unchanged(self):
        """Backward compatibility: existing types retain their values."""
        assert NetInterface.SMALL.rate == 10_000
        assert NetInterface.MEDIUM.rate == 10_000_000
        assert NetInterface.LARGE.rate == 10_000_000_000


class TestSpaceAntennas:
    """Verify LASER and HIGH_GAIN_PARABOLIC antenna types."""

    def test_laser_antenna_exists(self):
        ant = Antenna.LASER
        assert ant.value == 'laser'

    def test_high_gain_parabolic_exists(self):
        ant = Antenna.HIGH_GAIN_PARABOLIC
        assert ant.value == 'high_gain_parabolic'

    def test_laser_gain(self):
        assert Antenna.LASER.gain == 50.0  # dBi

    def test_high_gain_parabolic_gain(self):
        assert Antenna.HIGH_GAIN_PARABOLIC.gain == 45.0  # dBi

    def test_existing_antennas_unchanged(self):
        """Backward compatibility: existing types retain their values."""
        assert Antenna.DIPOLE.gain == 3.0
        assert Antenna.YAGI.gain == 12.0
        assert Antenna.PARABOLIC.gain == 25.0


class TestSpaceReceiverSensitivity:
    """Verify PeerConnection has sensitivity entries for space interfaces."""

    def test_laser_comms_sensitivity(self):
        assert PeerConnection._rx_sensitivity['laser_comms'] == -140.0

    def test_deep_space_sensitivity(self):
        assert PeerConnection._rx_sensitivity['deep_space'] == -150.0

    def test_existing_sensitivities_unchanged(self):
        assert PeerConnection._rx_sensitivity['small'] == -120.0
        assert PeerConnection._rx_sensitivity['medium'] == -90.0
        assert PeerConnection._rx_sensitivity['large'] == -70.0
