# ******************
#  Copyright 2024 TekFive, Inc. and contributors
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

from autonomous_trust.core.config import Configuration
from autonomous_trust.services.peer.position import Position

from ..radio.iface import NetInterface, Antenna
from .path import PathData, Path


class PeerConnection(Configuration):
    """Snapshot in time of peer connectivity"""
    def __init__(self, uuid: str, kind: str, nickname: str, ip4_addr: str, position: Position, signal: float,
                 antenna: Antenna, iface: NetInterface):
        super().__init__()
        self.uuid = uuid
        self.kind = kind
        self.nickname = nickname
        self.ip4_addr = ip4_addr
        self.position = position
        self.signal = signal
        self.iface = iface
        self.antenna = antenna

    def can_reach(self, other: 'PeerConnection') -> bool:
        min_strength = -154 * 10 * math.log10(self.iface.rate)  # dBm * 10log10(bps)
        dist = self.position.distance(other.position)
        if dist == 0:
            dist = .001
        signal_strength = (1.0 / (dist ** 2) * self.signal) + self.antenna.gain
        # dBm is negative, more negative is stronger
        return signal_strength < min_strength


class DataStream(Configuration):
    def __init__(self, filename: str, start: datetime, bps: float):
        super().__init__()
        self.filename = filename
        self.start = start
        self.bps = bps


class PeerInfo(PeerConnection):
    """Artificial, high-level hardware simulation data fed directly into a peer's system. Serializable."""
    def __init__(self, uuid: str, kind: str, nickname: str, ip4_addr: str, initial_position: Position,
                 signal: float, antenna: Antenna, iface: NetInterface,
                 initial_time: datetime, last_seen: datetime, path_list: list[PathData],
                 data_streams: list[DataStream]):
        super().__init__(uuid, kind, nickname, ip4_addr, initial_position, signal, antenna, iface)
        self.initial_time = initial_time
        self.last_seen = last_seen
        self.initial_position = initial_position
        self.path_list = path_list
        self.data_streams = data_streams

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
