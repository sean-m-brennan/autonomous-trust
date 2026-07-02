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

"""Tests for terrain-aware connectivity in the AT simulator.

Validates:
1. Backward compatibility: can_reach() without terrain data behaves as before
2. Terrain-aware reachability: high path loss -> unreachable
3. Terrain-aware reachability: low path loss -> reachable
4. SignalMatrix CSV round-trip via TerrainPathLoss
5. Appalachian scenario config creation
"""

import os
import tempfile

import pytest

try:
    from autonomous_trust.services.peer.position import GeoPosition, UTMPosition
    from autonomous_trust.simulator.peer.peer import PeerConnection
    from autonomous_trust.simulator.radio.iface import Antenna, NetInterface
    from autonomous_trust.simulator.radio.terrain import TerrainPathLoss
    from autonomous_trust.simulator.sim_data import SignalMatrix
    from autonomous_trust.simulator.radio.routing import Router
except ImportError as _e:
    pytestmark = pytest.mark.skip(reason=f"missing dependency: {_e}")
    GeoPosition = UTMPosition = PeerConnection = None
    Antenna = NetInterface = TerrainPathLoss = SignalMatrix = Router = None


# --- Fixtures ---

@pytest.fixture
def hilltop_pair():
    """Two hilltop peers ~22 km apart (Sutton-Burnsville from rural-network.md).

    For terrain-aware mode, signal is TX power in dBm.
    30 dBm = 1 W, typical for outdoor WiFi/mesh radios.
    """
    sutton_pos = GeoPosition(38.66, -80.71, 670).convert(UTMPosition)
    burnsville_pos = GeoPosition(38.85, -80.66, 730).convert(UTMPosition)
    sutton = PeerConnection(
        uuid='sutton-001', kind='hilltop_relay', petname='sutton_hilltop',
        ip4_addr='10.38.80.1', position=sutton_pos, signal=30.0,
        antenna=Antenna.YAGI, iface=NetInterface.MEDIUM,
    )
    burnsville = PeerConnection(
        uuid='burnsville-001', kind='hilltop_relay', petname='burnsville_hilltop',
        ip4_addr='10.38.80.2', position=burnsville_pos, signal=30.0,
        antenna=Antenna.YAGI, iface=NetInterface.MEDIUM,
    )
    return sutton, burnsville


@pytest.fixture
def valley_pair():
    """Two valley peers ~5 km apart with DIPOLE antennas.

    For terrain-aware mode, signal is TX power in dBm.
    20 dBm = 100 mW, typical for lower-power access nodes.
    """
    pos_a = GeoPosition(38.655, -80.710, 290).convert(UTMPosition)
    pos_b = GeoPosition(38.670, -80.770, 270).convert(UTMPosition)
    peer_a = PeerConnection(
        uuid='valley-001', kind='valley_relay', petname='sutton_valley',
        ip4_addr='10.38.80.10', position=pos_a, signal=20.0,
        antenna=Antenna.DIPOLE, iface=NetInterface.SMALL,
    )
    peer_b = PeerConnection(
        uuid='valley-002', kind='valley_relay', petname='gassaway_valley',
        ip4_addr='10.38.80.11', position=pos_b, signal=20.0,
        antenna=Antenna.DIPOLE, iface=NetInterface.SMALL,
    )
    return peer_a, peer_b


@pytest.fixture
def hilltop_pair_original():
    """Two hilltop peers using the original signal model (for backward compat tests)."""
    sutton_pos = GeoPosition(38.66, -80.71, 670).convert(UTMPosition)
    burnsville_pos = GeoPosition(38.85, -80.66, 730).convert(UTMPosition)
    sutton = PeerConnection(
        uuid='sutton-001', kind='hilltop_relay', petname='sutton_hilltop',
        ip4_addr='10.38.80.1', position=sutton_pos, signal=-200.,
        antenna=Antenna.YAGI, iface=NetInterface.MEDIUM,
    )
    burnsville = PeerConnection(
        uuid='burnsville-001', kind='hilltop_relay', petname='burnsville_hilltop',
        ip4_addr='10.38.80.2', position=burnsville_pos, signal=-200.,
        antenna=Antenna.YAGI, iface=NetInterface.MEDIUM,
    )
    return sutton, burnsville


@pytest.fixture
def sample_csv(tmp_path):
    """Create a sample path-loss CSV file."""
    csv_content = (
        "src_id,dst_id,freq_mhz,path_loss_db\n"
        "sutton_hilltop,burnsville_hilltop,5800,145.5\n"
        "burnsville_hilltop,sutton_hilltop,5800,145.5\n"
        "sutton_hilltop,burnsville_hilltop,2400,138.2\n"
        "burnsville_hilltop,sutton_hilltop,2400,138.2\n"
        "sutton_hilltop,burnsville_hilltop,900,125.0\n"
        "burnsville_hilltop,sutton_hilltop,900,125.0\n"
        "sutton_hilltop,powell_mtn,5800,128.3\n"
        "powell_mtn,sutton_hilltop,5800,128.3\n"
        "valley_a,valley_b,5800,180.0\n"
        "valley_b,valley_a,5800,180.0\n"
    )
    csv_file = tmp_path / 'test_path_loss.csv'
    csv_file.write_text(csv_content)
    return str(csv_file)


# --- Backward Compatibility Tests ---

def test_can_reach_without_terrain_returns_bool(hilltop_pair_original):
    """can_reach() without terrain data returns a boolean (original behavior)."""
    sutton, burnsville = hilltop_pair_original
    result = sutton.can_reach(burnsville)
    assert isinstance(result, bool)


def test_can_reach_without_terrain_unchanged(hilltop_pair_original):
    """can_reach() without terrain_loss_db uses original inverse-square model."""
    sutton, burnsville = hilltop_pair_original
    # Call without terrain data — should use original model
    result_no_terrain = sutton.can_reach(burnsville, terrain_loss_db=None)
    result_default = sutton.can_reach(burnsville)
    assert result_no_terrain == result_default


# --- Terrain-Aware Reachability Tests ---

def test_high_terrain_loss_unreachable(hilltop_pair):
    """A pair with very high terrain path loss is correctly marked unreachable.

    With 30 dBm TX, YAGI (12 dBi) each, MEDIUM sensitivity -90 dBm:
    received = 30 - 200 + 12 + 12 = -146 dBm < -90 → unreachable
    """
    sutton, burnsville = hilltop_pair
    result = sutton.can_reach(burnsville, terrain_loss_db=200.0)
    assert result is False


def test_low_terrain_loss_reachable(hilltop_pair):
    """A pair with low terrain path loss (clear LOS) is correctly marked reachable.

    With 30 dBm TX, YAGI (12 dBi) each, MEDIUM sensitivity -90 dBm:
    received = 30 - 100 + 12 + 12 = -46 dBm >= -90 → reachable
    """
    sutton, burnsville = hilltop_pair
    result = sutton.can_reach(burnsville, terrain_loss_db=100.0)
    assert result is True


def test_terrain_loss_marginal_link(hilltop_pair):
    """Terrain loss near the link budget threshold produces correct result.

    Link budget: 30 + 12 + 12 = 54 dBm total before path loss.
    Sensitivity: -90 dBm. Max tolerable loss: 54 + 90 = 144 dB.
    """
    sutton, burnsville = hilltop_pair
    assert sutton.can_reach(burnsville, terrain_loss_db=130.0) is True   # 14 dB margin
    assert sutton.can_reach(burnsville, terrain_loss_db=150.0) is False  # 6 dB over budget


def test_valley_high_terrain_loss(valley_pair):
    """Valley nodes with ridge between them are blocked by terrain.

    With 20 dBm TX, DIPOLE (3 dBi) each, SMALL sensitivity -120 dBm:
    Max tolerable loss: 20 + 3 + 3 + 120 = 146 dB.
    190 dB loss → unreachable.
    """
    a, b = valley_pair
    result = a.can_reach(b, terrain_loss_db=190.0)
    assert result is False


def test_valley_low_terrain_loss_reachable(valley_pair):
    """Valley nodes with clear path are reachable.

    With 20 dBm TX, DIPOLE (3 dBi) each, SMALL sensitivity -120 dBm:
    received = 20 - 80 + 3 + 3 = -54 dBm >= -120 → reachable
    """
    a, b = valley_pair
    result = a.can_reach(b, terrain_loss_db=80.0)
    assert result is True


# --- TerrainPathLoss CSV Tests ---

def test_load_csv_frequencies(sample_csv):
    """CSV loads correctly and reports all frequencies."""
    terrain = TerrainPathLoss()
    terrain.load_csv(sample_csv)
    assert sorted(terrain.frequencies) == [900.0, 2400.0, 5800.0]


def test_load_csv_matrix_values(sample_csv):
    """CSV values are correctly loaded into SignalMatrix."""
    terrain = TerrainPathLoss()
    terrain.load_csv(sample_csv)
    matrix = terrain.get_matrix(5800.0)
    assert matrix is not None
    assert matrix['sutton_hilltop']['burnsville_hilltop'] == 145.5
    assert matrix['burnsville_hilltop']['sutton_hilltop'] == 145.5
    assert matrix['sutton_hilltop']['powell_mtn'] == 128.3


def test_load_csv_missing_frequency(sample_csv):
    """Requesting a frequency not in the CSV returns None."""
    terrain = TerrainPathLoss()
    terrain.load_csv(sample_csv)
    assert terrain.get_matrix(1800.0) is None


def test_get_loss_specific_pair(sample_csv):
    """get_loss() returns correct value for a specific pair."""
    terrain = TerrainPathLoss()
    terrain.load_csv(sample_csv)
    loss = terrain.get_loss(5800.0, 'sutton_hilltop', 'burnsville_hilltop')
    assert loss == 145.5


def test_get_loss_missing_pair(sample_csv):
    """get_loss() returns None for a pair not in the matrix."""
    terrain = TerrainPathLoss()
    terrain.load_csv(sample_csv)
    assert terrain.get_loss(5800.0, 'sutton_hilltop', 'nonexistent') is None


def test_csv_round_trip(sample_csv, tmp_path):
    """Save and reload CSV produces identical data."""
    terrain = TerrainPathLoss()
    terrain.load_csv(sample_csv)

    out_path = str(tmp_path / 'round_trip.csv')
    terrain.save_csv(out_path)

    terrain2 = TerrainPathLoss()
    terrain2.load_csv(out_path)

    for freq in terrain.frequencies:
        m1 = terrain.get_matrix(freq)
        m2 = terrain2.get_matrix(freq)
        assert m1 is not None
        assert m2 is not None
        for src in m1:
            for dst in m1[src]:
                assert m1[src][dst] == m2[src][dst]


# --- Appalachian Scenario Tests ---

def test_appalachian_config_creation():
    """Appalachian scenario config creates without error."""
    from examples.appalachia.scenario import create_appalachian_config
    with tempfile.NamedTemporaryFile(suffix='.cfg', delete=False) as f:
        cfg_path = f.name
    try:
        result = create_appalachian_config(output_file=cfg_path)
        assert os.path.exists(result)
        assert os.path.getsize(result) > 0
    finally:
        if os.path.exists(cfg_path):
            os.remove(cfg_path)


def test_appalachian_hilltop_only():
    """Hilltop-only scenario has 8 peers."""
    from examples.appalachia.scenario import create_appalachian_config
    from autonomous_trust.simulator.sim_data import SimConfig
    with tempfile.NamedTemporaryFile(suffix='.cfg', delete=False) as f:
        cfg_path = f.name
    try:
        create_appalachian_config(output_file=cfg_path, hilltop_only=True)
        with open(cfg_path, 'r') as f:
            cfg = SimConfig.load(f.read())
        assert len(cfg.peers) == 8
        assert all(p.kind == 'hilltop_relay' for p in cfg.peers)
    finally:
        if os.path.exists(cfg_path):
            os.remove(cfg_path)


def test_appalachian_full_scenario():
    """Full scenario has 20 peers (8 hilltop + 12 valley)."""
    from examples.appalachia.scenario import create_appalachian_config
    from autonomous_trust.simulator.sim_data import SimConfig
    with tempfile.NamedTemporaryFile(suffix='.cfg', delete=False) as f:
        cfg_path = f.name
    try:
        create_appalachian_config(output_file=cfg_path)
        with open(cfg_path, 'r') as f:
            cfg = SimConfig.load(f.read())
        assert len(cfg.peers) == 20
        hilltop_count = sum(1 for p in cfg.peers if p.kind == 'hilltop_relay')
        valley_count = sum(1 for p in cfg.peers if p.kind == 'valley_relay')
        assert hilltop_count == 8
        assert valley_count == 12
    finally:
        if os.path.exists(cfg_path):
            os.remove(cfg_path)


def test_appalachian_splat_sites():
    """get_splat_sites() returns correct count and format."""
    from examples.appalachia.scenario import get_splat_sites
    sites = get_splat_sites()
    assert len(sites) == 20
    # Hilltop sites have 12m masts, valley sites have 6m
    hilltop_sites = [s for s in sites if s.height_m == 12.0]
    valley_sites = [s for s in sites if s.height_m == 6.0]
    assert len(hilltop_sites) == 8
    assert len(valley_sites) == 12


# --- Router Bandwidth Degradation Tests ---

def test_degraded_rate_full_at_low_loss():
    """Full bandwidth at low path loss."""
    rate = Router.degraded_rate(10_000_000, 60.0)  # 10 Mbps, 60 dB loss
    assert rate == '10Mbit'


def test_degraded_rate_minimum_at_high_loss():
    """Minimum bandwidth at very high path loss."""
    rate = Router.degraded_rate(10_000_000, 200.0)  # 10 Mbps, 200 dB loss
    # 1% of 10 Mbps = 100 Kbps
    assert rate == '100Kbit'


def test_degraded_rate_intermediate():
    """Intermediate path loss produces intermediate rate."""
    # At midpoint of range (120 dB), should be ~50% rate
    rate = Router.degraded_rate(10_000_000, 120.0)
    # 120 dB is midpoint between 80 and 160, so fraction ~ 0.505
    # 10 Mbps * 0.505 = ~5.05 Mbps -> '5Mbit'
    assert rate == '5Mbit'


def test_degraded_rate_kbit_range():
    """Small interface produces Kbit rates."""
    rate = Router.degraded_rate(10_000, 60.0)  # 10 Kbps, low loss -> full
    assert rate == '10Kbit'


def test_degraded_rate_floor():
    """Rate never drops below 1 Kbps."""
    rate = Router.degraded_rate(100, 200.0)  # 100 bps * 0.01 = 1 bps, but floor is 1000
    assert rate == '1Kbit'


# --- Router parse_chain Tests (R11) ---

def test_parse_chain_finds_matching_rule():
    """parse_chain correctly identifies matching src/dst in iptables output."""
    from unittest.mock import patch
    router = Router.__new__(Router)
    # Simulate iptables -L output (first 2 lines are header, then rules)
    mock_output = [
        'Chain FORWARD (policy ACCEPT)',
        'target     prot opt source               destination',
        'DROP       all  --  10.38.80.1           10.38.80.2',
        'DROP       all  --  10.38.80.3           anywhere',
    ]
    with patch.object(Router, 'iptables', return_value=mock_output):
        assert router.parse_chain('FORWARD', '10.38.80.1', '10.38.80.2') is True
        assert router.parse_chain('FORWARD', '10.38.80.3', None) is True
        assert router.parse_chain('FORWARD', '10.38.80.1', '10.38.80.3') is False


def test_parse_chain_no_src_no_dst_returns_false():
    """parse_chain returns False when both src and dst are None."""
    router = Router.__new__(Router)
    assert router.parse_chain('FORWARD', None, None) is False


def test_parse_chain_empty_chain():
    """parse_chain returns False for empty iptables chain."""
    from unittest.mock import patch
    router = Router.__new__(Router)
    mock_output = [
        'Chain FORWARD (policy ACCEPT)',
        'target     prot opt source               destination',
    ]
    with patch.object(Router, 'iptables', return_value=mock_output):
        assert router.parse_chain('FORWARD', '10.0.0.1', '10.0.0.2') is False
