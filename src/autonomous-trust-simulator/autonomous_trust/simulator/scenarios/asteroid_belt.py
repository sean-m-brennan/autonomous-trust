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

"""Asteroid belt inter-habitat mesh scenario.

Defines 7 habitats on Keplerian solar orbits in the main asteroid belt
(2.0-3.5 AU).  Orbital parameters are inspired by real belt objects but
represent constructed habitats, not asteroids.

Physics summary (from system-simulation.md):
  - Inter-habitat distance: 2-4 AU (300M-600M km)
  - One-way light time: 16-64 minutes
  - Available bandwidth: 1 Kbps - 10 Mbps (distance-dependent)
  - Power: solar at ~14% Earth flux (2.7 AU mid-belt)

Coordinate system: UTMPosition with dummy zone '1N'.  Easting/northing
represent heliocentric x/y in meters.  EllipseData/EllipsePath handle
orbital motion via de La Hire's construction.
"""

import math
import os
import uuid
from datetime import datetime, timedelta
from typing import Optional

from autonomous_trust.services.peer.position import UTMPosition

from ..peer.path import EllipseData, PathData, Variability
from ..peer.peer import PeerInfo, DataStream
from ..radio.iface import Antenna, NetInterface
from ..radio.space_link import AU_M
from ..sim_data import SimConfig


DUMMY_ZONE = '1N'

# Sun at the origin of the heliocentric coordinate frame
SUN_POSITION = UTMPosition(DUMMY_ZONE, 0.0, 0.0, 0.0)

# Habitat definitions: orbital parameters inspired by real belt objects
HABITATS = [
    {
        'name': 'ceres_station',
        'semi_major_au': 2.77,
        'eccentricity': 0.076,
        'angle_deg': 0.0,
        'iface': NetInterface.LASER_COMMS,
        'antenna': Antenna.LASER,
        'signal_dbm': 43.0,
    },
    {
        'name': 'vesta_colony',
        'semi_major_au': 2.36,
        'eccentricity': 0.089,
        'angle_deg': 45.0,
        'iface': NetInterface.LASER_COMMS,
        'antenna': Antenna.LASER,
        'signal_dbm': 43.0,
    },
    {
        'name': 'pallas_outpost',
        'semi_major_au': 2.77,
        'eccentricity': 0.231,
        'angle_deg': 120.0,
        'iface': NetInterface.DEEP_SPACE,
        'antenna': Antenna.HIGH_GAIN_PARABOLIC,
        'signal_dbm': 47.0,
    },
    {
        'name': 'hygiea_hab',
        'semi_major_au': 3.14,
        'eccentricity': 0.117,
        'angle_deg': 200.0,
        'iface': NetInterface.DEEP_SPACE,
        'antenna': Antenna.HIGH_GAIN_PARABOLIC,
        'signal_dbm': 47.0,
    },
    {
        'name': 'juno_relay',
        'semi_major_au': 2.67,
        'eccentricity': 0.256,
        'angle_deg': 170.0,
        'iface': NetInterface.LASER_COMMS,
        'antenna': Antenna.LASER,
        'signal_dbm': 43.0,
    },
    {
        'name': 'davida_mining',
        'semi_major_au': 3.17,
        'eccentricity': 0.187,
        'angle_deg': 290.0,
        'iface': NetInterface.DEEP_SPACE,
        'antenna': Antenna.HIGH_GAIN_PARABOLIC,
        'signal_dbm': 47.0,
    },
    {
        'name': 'europa_far',
        'semi_major_au': 2.09,
        'eccentricity': 0.101,
        'angle_deg': 330.0,
        'iface': NetInterface.LASER_COMMS,
        'antenna': Antenna.LASER,
        'signal_dbm': 43.0,
    },
]


def _generate_uuid(name: str) -> str:
    """Generate a deterministic UUID from habitat name."""
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, 'muudd.asteroid_belt.%s' % name))


def _generate_ip(index: int) -> str:
    """Generate a deterministic IP address for a habitat."""
    return '10.99.0.%d' % (index + 1)


def create_asteroid_belt_config(
        output_file: Optional[str] = None,
        duration: timedelta = None,
        start: datetime = None,
        comm_freq_hz: float = 8.4e9,
        habitats: Optional[list[dict]] = None,
) -> str:
    if output_file is None:
        output_file = os.path.join(os.path.dirname(__file__), 'asteroid_belt.cfg')
    if start is None:
        start = datetime(2026, 1, 1)
    if duration is None:
        duration = timedelta(days=15 * 365)  # 15 years: long enough for differential orbital motion
    if habitats is None:
        habitats = HABITATS
    end = start + duration

    peers = []
    for idx, hab in enumerate(habitats):
        name = hab['name']
        a_m = hab['semi_major_au'] * AU_M
        e = hab['eccentricity']
        b_m = a_m * math.sqrt(1.0 - e * e)
        angle = hab['angle_deg']

        node_uuid = _generate_uuid(name)
        ip_addr = _generate_ip(idx)

        orbit_start = UTMPosition(
            DUMMY_ZONE,
            a_m * math.cos(math.radians(angle)),
            b_m * math.sin(math.radians(angle)),
            0.0,
        )

        # Kepler's third law: orbital period = a^1.5 years
        # Compute loops so each habitat orbits at its correct rate
        orbital_period_days = (hab['semi_major_au'] ** 1.5) * 365.25
        loops = max(1, round(duration.total_seconds() / (orbital_period_days * 86400)))

        shape = EllipseData(SUN_POSITION, a_m, b_m, angle, loops=loops)
        path_data = PathData(start, end, shape, Variability.UNIFORM, 0, Variability.UNIFORM)

        peers.append(PeerInfo(
            uuid=node_uuid,
            kind='habitat',
            nickname=name,
            ip4_addr=ip_addr,
            initial_position=orbit_start,
            signal=hab['signal_dbm'],
            antenna=hab['antenna'],
            iface=hab['iface'],
            initial_time=start,
            last_seen=end,
            path_list=[path_data],
            data_streams=[],
        ))

    config = SimConfig(
        start=start, end=end, peers=peers,
        space_mode=True,
        comm_freq_hz=comm_freq_hz,
        sun_position=SUN_POSITION,
    )
    config.to_file(output_file)
    return output_file
