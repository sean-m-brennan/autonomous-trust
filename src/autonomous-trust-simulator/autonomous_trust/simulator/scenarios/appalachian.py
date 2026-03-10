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

"""Braxton County, WV Appalachian mesh network scenario.

Defines the Sutton-Burnsville-Flatwoods triangle from network.md:
  - 8 hilltop relay nodes on ridgetops (Tier 1)
  - 12 valley relay nodes in hollows/valley floors (Tier 2)
  - Stationary positions (PointData paths)
  - Appropriate antenna and interface assignments per node tier

Coordinates are based on real Braxton County geography:
  - Sutton hilltop: 38.66N, 80.71W, ~670m (2200 ft) — from network.md
  - Burnsville hilltop: 38.85N, 80.66W, ~730m (2400 ft) — from network.md
  - Flatwoods gateway: 38.73N, 80.65W, ~580m (1900 ft) — I-79 corridor
  - Ridgeline elevations: 550-850m; valley floors: 240-370m
"""

import os
import uuid
from datetime import datetime, timedelta
from typing import Optional

from autonomous_trust.services.peer.position import GeoPosition, UTMPosition

from ..peer.path import PointData, PathData, Variability
from ..peer.peer import PeerInfo, DataStream
from ..radio.iface import Antenna, NetInterface
from ..radio.terrain import TerrainPathLoss, SplatSite
from ..sim_data import SimConfig, SignalMatrix


# Braxton County node definitions
# Hilltop relays (Tier 1): ridgetop positions with YAGI antennas, MEDIUM interfaces
# Coordinates derived from network.md worked examples and Braxton County geography

HILLTOP_NODES = [
    # (name, lat, lon, elevation_m)
    ('sutton_hilltop',     38.660, -80.710, 670),   # Ridgetop above Sutton (network.md)
    ('burnsville_hilltop', 38.850, -80.660, 730),   # Ridgetop above Burnsville (network.md)
    ('powell_mtn',         38.720, -80.750, 790),   # Powell Mountain — backbone node
    ('otter_creek_ridge',  38.790, -80.620, 710),   # Otter Creek Ridge — backbone node
    ('flatwoods_hilltop',  38.740, -80.640, 610),   # Ridge above Flatwoods — gateway site
    ('elk_ridge',          38.680, -80.640, 680),    # Ridge between Sutton and Flatwoods
    ('birch_mtn',          38.630, -80.760, 750),    # SW of Sutton, Birch River drainage
    ('centralia_ridge',    38.760, -80.710, 700),    # Ridge above Centralia valley
]

# Valley relays (Tier 2): valley floor positions with DIPOLE antennas, SMALL interfaces
# These extend coverage from hilltop relays into hollows

VALLEY_NODES = [
    # (name, lat, lon, elevation_m)
    ('sutton_valley_1',     38.655, -80.710, 290),  # Sutton — Elk River bank
    ('sutton_valley_2',     38.648, -80.720, 300),  # Sutton south — along Elk River
    ('burnsville_valley_1', 38.852, -80.655, 275),  # Burnsville — Little Kanawha bank
    ('burnsville_valley_2', 38.858, -80.648, 280),  # Burnsville north
    ('flatwoods_valley',    38.732, -80.650, 350),  # Flatwoods — I-79 corridor floor
    ('gassaway_valley',     38.670, -80.770, 270),  # Gassaway — Elk River
    ('centralia_valley',    38.755, -80.700, 310),  # Centralia — between ridges
    ('birch_river_valley',  38.620, -80.750, 260),  # Birch River settlement
    ('holly_junction',      38.700, -80.680, 320),  # Holly River junction
    ('strange_creek',       38.690, -80.640, 330),  # Strange Creek area
    ('heaters_valley',      38.710, -80.730, 305),  # Heaters — along Elk River
    ('frametown_valley',    38.640, -80.690, 285),  # Frametown — below Elk Ridge
]


def _generate_uuid(name: str) -> str:
    """Generate a deterministic UUID from a node name for reproducibility."""
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, 'muudd.appalachian.%s' % name))


def _generate_ip(index: int) -> str:
    """Generate a deterministic IP address for a node."""
    return '10.38.80.%d' % (index + 1)


def get_splat_sites() -> list[SplatSite]:
    """Get all node positions as SplatSite objects for SPLAT! batch runs."""
    sites = []
    for name, lat, lon, elev in HILLTOP_NODES:
        sites.append(SplatSite(name, name.replace('_', ' ').title(), lat, lon, 12.0))  # 12m mast
    for name, lat, lon, elev in VALLEY_NODES:
        sites.append(SplatSite(name, name.replace('_', ' ').title(), lat, lon, 6.0))  # 6m mast
    return sites


def create_appalachian_config(
        output_file: Optional[str] = None,
        duration: timedelta = None,
        start: datetime = None,
        path_loss_matrix: Optional[SignalMatrix] = None,
        hilltop_only: bool = False,
) -> str:
    """Create a SimConfig for the Braxton County Appalachian scenario.

    Args:
        output_file: Path to write the config JSON. Defaults to a temp file.
        duration: Simulation duration. Defaults to 60 minutes.
        start: Simulation start time. Defaults to now.
        path_loss_matrix: Optional terrain-aware path-loss data (from SPLAT!).
            Keys are node UUIDs. If None, simulator uses inverse-square fallback.
        hilltop_only: If True, only include 8 hilltop relays (smaller scenario).

    Returns:
        Path to the generated config file.
    """
    if output_file is None:
        output_file = os.path.join(os.path.dirname(__file__), 'appalachian.cfg')
    if start is None:
        start = datetime.now().replace(microsecond=0, second=0, minute=0)
    if duration is None:
        duration = timedelta(minutes=60)
    end = start + duration

    # TX power in dBm for terrain-aware scenarios (standard RF link budget).
    # 30 dBm = 1 W — typical for outdoor mesh radios (MikroTik, Ubiquiti).
    # 20 dBm = 100 mW — typical for lower-power valley access nodes.
    # When path_loss_matrix is None, the original inverse-square model is used
    # and these values are interpreted differently (see PeerConnection.can_reach).
    hilltop_signal = 30.0   # dBm
    valley_signal = 20.0    # dBm

    peers = []
    node_index = 0

    # Hilltop relays (Tier 1)
    for name, lat, lon, elev in HILLTOP_NODES:
        node_uuid = _generate_uuid(name)
        ip_addr = _generate_ip(node_index)
        position = GeoPosition(lat, lon, elev).convert(UTMPosition)
        shape = PointData(position)
        path_data = PathData(start, end, shape, Variability.UNIFORM, 0, Variability.UNIFORM)
        peers.append(PeerInfo(
            uuid=node_uuid,
            kind='hilltop_relay',
            nickname=name,
            ip4_addr=ip_addr,
            initial_position=position,
            signal=hilltop_signal,
            antenna=Antenna.YAGI,
            iface=NetInterface.MEDIUM,
            initial_time=start,
            last_seen=end,
            path_list=[path_data],
            data_streams=[],
        ))
        node_index += 1

    # Valley relays (Tier 2)
    if not hilltop_only:
        for name, lat, lon, elev in VALLEY_NODES:
            node_uuid = _generate_uuid(name)
            ip_addr = _generate_ip(node_index)
            position = GeoPosition(lat, lon, elev).convert(UTMPosition)
            shape = PointData(position)
            path_data = PathData(start, end, shape, Variability.UNIFORM, 0, Variability.UNIFORM)
            peers.append(PeerInfo(
                uuid=node_uuid,
                kind='valley_relay',
                nickname=name,
                ip4_addr=ip_addr,
                initial_position=position,
                signal=valley_signal,
                antenna=Antenna.DIPOLE,
                iface=NetInterface.SMALL,
                initial_time=start,
                last_seen=end,
                path_list=[path_data],
                data_streams=[],
            ))
            node_index += 1

    config = SimConfig(start=start, end=end, peers=peers, path_loss_matrix=path_loss_matrix)
    config.to_file(output_file)
    return output_file


def load_terrain_matrix(csv_path: str, freq_mhz: float,
                        node_names: Optional[list[str]] = None) -> SignalMatrix:
    """Load a SPLAT! path-loss CSV and convert node names to UUIDs.

    Args:
        csv_path: Path to CSV file with columns: src_id, dst_id, freq_mhz, path_loss_db
        freq_mhz: Frequency to extract from the CSV.
        node_names: If provided, only include these node names. Otherwise use all.

    Returns:
        SignalMatrix keyed by node UUIDs.
    """
    terrain = TerrainPathLoss()
    terrain.load_csv(csv_path)
    name_matrix = terrain.get_matrix(freq_mhz)
    if name_matrix is None:
        return {}

    # Convert name-keyed matrix to UUID-keyed matrix
    uuid_matrix: SignalMatrix = {}
    for src_name, destinations in name_matrix.items():
        if node_names is not None and src_name not in node_names:
            continue
        src_uuid = _generate_uuid(src_name)
        uuid_matrix[src_uuid] = {}
        for dst_name, loss in destinations.items():
            if node_names is not None and dst_name not in node_names:
                continue
            dst_uuid = _generate_uuid(dst_name)
            uuid_matrix[src_uuid][dst_uuid] = loss

    return uuid_matrix
