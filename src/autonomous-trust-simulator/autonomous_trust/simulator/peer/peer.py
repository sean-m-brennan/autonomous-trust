# ******************
#  Copyright 2023 TekFive, Inc., Sean M. Brennan, and contributors
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

import math
from datetime import datetime, timedelta
from typing import Optional

import icontract

from autonomous_trust.core.config import Configuration
from autonomous_trust.services.peer.position import Position

from ..radio.iface import NetInterface, Antenna
from .path import PathData, Path


class PeerConnection(Configuration):
    """Snapshot in time of peer connectivity"""
    def __init__(self, uuid: str, kind: str, petname: str, ip4_addr: str, position: Position, signal: float,
                 antenna: Antenna, iface: NetInterface):
        super().__init__()
        self.uuid = uuid
        self.kind = kind
        self.petname = petname
        self.ip4_addr = ip4_addr
        self.position = position
        self.signal = signal
        self.iface = iface
        self.antenna = antenna

    # Receiver sensitivity thresholds (dBm) by NetInterface class
    # Used only in terrain-aware mode; original model uses its own formula
    _rx_sensitivity = {
        'small': -120.0,        # LoRa-class: very sensitive, low data rate
        'medium': -90.0,        # WiFi-class: typical 802.11 receiver
        'large': -70.0,         # High-bandwidth point-to-point
        'laser_comms': -140.0,  # Optical photon-counting detector (deep-space grade)
        'deep_space': -150.0,   # DSN-class cryogenic receiver
    }

    def can_reach(self, other: 'PeerConnection', terrain_loss_db: Optional[float] = None) -> bool:
        """Determine if this peer can reach another.

        When terrain_loss_db is provided (from SPLAT! or similar), uses a
        standard RF link budget: received_power = tx_power - path_loss + tx_gain + rx_gain.
        Link is viable if received_power >= receiver_sensitivity.

        When terrain_loss_db is None, falls back to the original inverse-square
        model for backward compatibility with existing tactical scenarios.
        """
        if terrain_loss_db is not None:
            # Terrain-aware: standard RF link budget in dB scale
            # tx_power_dbm is stored directly in self.signal for terrain scenarios
            received_power = self.signal - terrain_loss_db + self.antenna.gain + other.antenna.gain
            sensitivity = self._rx_sensitivity.get(self.iface.value, -90.0)
            return received_power >= sensitivity
        else:
            # Original inverse-square model (backward compatibility)
            min_strength = -154 * 10 * math.log10(self.iface.rate)
            dist = self.position.distance(other.position)
            if dist == 0:
                dist = .001
            signal_strength = (1.0 / (dist ** 2) * self.signal) + self.antenna.gain
            # Signal must exceed minimum threshold to reach peer
            return signal_strength > min_strength


class GatewayUplink(Configuration):
    """Internet egress capability for a gateway node."""

    @icontract.require(lambda bandwidth_down_mbps: bandwidth_down_mbps > 0)
    @icontract.require(lambda bandwidth_up_mbps: bandwidth_up_mbps > 0)
    @icontract.require(lambda reliability: 0.0 <= reliability <= 1.0)
    def __init__(self, technology: str, bandwidth_down_mbps: float,
                 bandwidth_up_mbps: float, reliability: float = 0.99):
        super().__init__()
        self.technology = technology
        self.bandwidth_down_mbps = bandwidth_down_mbps
        self.bandwidth_up_mbps = bandwidth_up_mbps
        self.reliability = reliability


class DataStream(Configuration):
    def __init__(self, filename: str, start: datetime, bps: float):
        super().__init__()
        self.filename = filename
        self.start = start
        self.bps = bps


class PeerInfo(PeerConnection):
    """Artificial, high-level hardware simulation data fed directly into a peer's system. Serializable."""
    def __init__(self, uuid: str, kind: str, petname: str, ip4_addr: str, initial_position: Position,
                 signal: float, antenna: Antenna, iface: NetInterface,
                 initial_time: datetime, last_seen: datetime, path_list: list[PathData],
                 data_streams: list[DataStream], uplink: Optional[GatewayUplink] = None):
        super().__init__(uuid, kind, petname, ip4_addr, initial_position, signal, antenna, iface)
        self.initial_time = initial_time
        self.last_seen = last_seen
        self.initial_position = initial_position
        self.path_list = path_list
        self.data_streams = data_streams
        self.uplink = uplink

    @property
    def connection(self) -> PeerConnection:
        return super()

    def to_dict(self) -> dict:
        d = super().to_dict()
        for param in ['position']:
            del d[param]
        return d


class PeerMovement(object):
    """Step-wise peer movement along a path"""
    def __init__(self, start: datetime, sim_cadence: float, path_data: list[PathData]):
        self.start = start
        self.cadence = sim_cadence
        self.paths: list[Path] = []
        for path in path_data:
            sub_steps = int((path.end - path.begin).total_seconds() / self.cadence)
            self.paths.append(Path(sub_steps, sim_cadence, path, start))
        self.prev = None

    def move(self, step: int) -> tuple[Optional[Position], Optional[float]]:
        current_time = self.start + timedelta(seconds=self.cadence * step)
        sub_steps = [path.sub_steps for path in self.paths]
        for idx, path in enumerate(self.paths):
            prev = sum(sub_steps[:idx])
            if path.data.begin <= current_time <= path.data.end:
                if self.prev is None or path != self.prev:
                    if step != path.offset:
                        return None, None
                self.prev = path
                return path.move_along(step - prev)
        return None, None
