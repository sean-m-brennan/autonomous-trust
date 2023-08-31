import math
from datetime import datetime

from ..util import Serializable
from ..radio.iface import NetInterface
from .position import Position
from .path import PathData, Path


class PeerConnection(Serializable):
    """Snapshot in time of peer connectivity"""
    def __init__(self, uuid: str, ip4_addr: str, position: Position, signal: float,
                 antenna_gain: float, iface: NetInterface):
        self.uuid = uuid
        self.ip4_addr = ip4_addr
        self.position = position
        self.signal = signal
        self.iface = iface
        self.antenna_gain = antenna_gain

    def can_reach(self, other: 'PeerConnection') -> bool:
        min_strength = -154 * 10 * math.log10(self.iface.rate * 1000000)  # dBm * 10log10(bps)
        signal_strength = (1.0 / (self.position.distance(other.position) ** 2) * self.signal) + self.antenna_gain
        # dBm is negative, more negative is stronger
        return signal_strength < min_strength


class DataStream(Serializable):
    def __init__(self, filename: str, start: datetime, bps: float):
        self.filename = filename
        self.start = start
        self.bps = bps


class PeerData(PeerConnection):
    def __init__(self, uuid: str, ip4_addr: str, position: Position,
                 signal: float, antenna: float, iface: NetInterface,
                 initial_time: datetime, last_seen: datetime, path: PathData,
                 data_streams: list[DataStream]):
        super().__init__(uuid, ip4_addr, position, signal, antenna, iface)
        self.initial_time = initial_time
        self.last_seen = last_seen
        self.initial_position = position
        self.path = path
        self.data_streams = data_streams

    @property
    def connection(self) -> PeerConnection:
        return super()


class Peer(object):
    def __init__(self, sim_steps: int, sim_cadence: float, path_data: PathData):
        self.path = Path(sim_steps, sim_cadence, path_data)

    def move(self, step: int) -> Position:
        return self.path.move_along(step)
