import math
from datetime import datetime

from autonomous_trust.core.config import Configuration
from ..radio.iface import NetInterface, Antenna
from .position import Position
from .path import PathData, Path


class PeerConnection(Configuration):
    """Snapshot in time of peer connectivity"""
    def __init__(self, uuid: str, kind: str, ip4_addr: str, position: Position, signal: float,
                 antenna: Antenna, iface: NetInterface):
        super().__init__()
        self.uuid = uuid
        self.kind = kind
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
    def __init__(self, uuid: str, kind: str, ip4_addr: str, initial_position: Position,
                 signal: float, antenna: Antenna, iface: NetInterface,
                 initial_time: datetime, last_seen: datetime, path: PathData,
                 data_streams: list[DataStream]):
        super().__init__(uuid, kind, ip4_addr, initial_position, signal, antenna, iface)
        self.initial_time = initial_time
        self.last_seen = last_seen
        self.initial_position = initial_position
        self.path = path
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
    def __init__(self, sim_steps: int, sim_cadence: float, path_data: PathData):
        self.path = Path(sim_steps, sim_cadence, path_data)

    def move(self, step: int) -> Position:
        return self.path.move_along(step)
