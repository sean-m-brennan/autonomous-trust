import json
import math
import socket
import time
from enum import Enum
from typing import Optional

from . import net_util as net


class Serializable(object):
    def to_json(self):
        json.dumps(self, default=lambda obj: obj.__dict__)


class Position(Serializable):
    def distance(self, other: 'Position'):
        raise NotImplementedError


class GeoPosition(Position):
    def __init__(self, lat: float, lon: float, alt: Optional[float] = None):
        """Specified in decimal degrees, plus meters for altitude"""
        super().__init__(lat, lon, alt)
        self.lat = lat
        self.lon = lon
        self.alt = alt

    def convert(self, ref: 'GeoPosition'):
        """Convert to UTM"""
        lat_dist = GeoPosition(self.lat, ref.lon).distance(ref)
        lon_dist = GeoPosition(ref.lat, self.lon).distance(ref)
        return UTMPosition(ref, lon_dist, lat_dist, self.alt)

    def distance(self, other: 'GeoPosition'):
        """
        Haversine method: the great circle distance over Earth in meters
        """
        lon1, lat1, lon2, lat2 = map(math.radians, [self.lon, self.lat, other.lon, other.lat])
        mean_radius = 6371000  # meters
        delta_lon = lon2 - lon1
        delta_lat = lat2 - lat1
        a = math.sin(delta_lat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(delta_lon / 2) ** 2
        c = 2 * math.asin(math.sqrt(a))
        d = mean_radius * c
        if self.alt is not None and other.alt is not None:
            delta_alt = self.alt - other.alt
            d = math.sqrt(delta_alt ** 2 + d ** 2)
        return d


class UTMPosition(Position):
    def __init__(self, ref: GeoPosition, easting: float, northing: float, alt: Optional[float] = None,
                 north: bool = True):
        """
        Easting/northing/altitude specified in meters;
        reference geo point is the intersection of the UTM zone's central meridian and the equator;
        reference point is at 500000m east, at 0m for the Northern hemisphere, 10000000m for the South
        """
        super().__init__(easting, northing, alt)
        self.base = ref
        self.base.alt = 0  # enforce base point characteristics
        self.base.lon = 0.
        self.easting = easting
        self.northing = northing
        self.alt = alt
        self.north = north

    def distance(self, other: 'Position'):
        if isinstance(other, GeoPosition):  # convert Geo to UTM in the same zone
            other = other.convert(self.base)

        delta_lat = 0
        if self.base != other.base:
            delta_lat = self.base.lat - other.base.lat  # lon delta will be zero

        sum_sq = ((self.easting - other.easting + delta_lat) ** 2) + \
                 ((self.northing - other.northing) ** 2)
        if self.alt is not None and other.alt is not None:
            sum_sq += (self.alt - other.alt) ** 2
        return math.sqrt(sum_sq)


class NetInterface(Serializable):
    def __init__(self, rate: int, mark: int):
        self.rate = rate
        self.mark = mark


class InterfaceClasses(NetInterface, Enum):
    SMALL = NetInterface(10 * 1000, 11)  # 10Kbps
    MEDIUM = NetInterface(10 * 1000 * 1000, 22)  # 10Mbps
    LARGE = NetInterface(10 * 1000 * 1000 * 1000, 33)  # 10Gbps


class Peer(Serializable):
    def __init__(self, uuid: str, position: Position, signal: float, iface: NetInterface):
        self.uuid = uuid
        self.position = position
        self.signal = signal
        self.iface = iface

    def move(self, pos: Position):
        self.position = pos

    def can_reach(self, other: 'Peer') -> bool:
        min_strength = -154 * 10 * math.log10(self.iface.rate * 1000000)  # dBm * 10log10(bps)
        # dBm is negative, more negative is stronger
        return (1.0 / (self.position.distance(other.position) ** 2) * self.signal) < min_strength


class SimState(Serializable):
    def __init__(self, peers: list[Peer] = None, reachable: dict[str, dict[str, bool]] = None):
        self.peers = peers
        if peers is None:
            self.peers = []
        self.reachable = reachable
        if reachable is None:
            self.reachable = {}

    def add_peer(self, peer: Peer):
        others = list(self.peers)
        self.peers.append(peer)
        self.reachable[peer.uuid] = dict({})
        for other in others:
            self.reachable[peer.uuid][other.uuid] = peer.can_reach(other)

    def move_peer(self, peer: Peer, pos: Position):
        peer.move(pos)
        others = [p for p in self.peers if p != peer]
        for other in others:
            self.reachable[peer.uuid][other.uuid] = peer.can_reach(other)


class SimConfig(Serializable):
    def __init__(self, **kwargs):
        pass  # FIXME populate

    @classmethod
    def load(cls, data):
        return SimConfig(**(json.loads(data)))


class Simulator(net.SelectServer):
    header_fmt = '!Q'

    def __init__(self, cfg_file_path: str):
        super().__init__()
        with open(cfg_file_path, 'r') as cfg_file:
            self.cfg = SimConfig.load(cfg_file.read())
        self.state = SimState()
        self.precompute()
        self.tick = 0

    def precompute(self):
        pass  # FIXME precompute positions, net reachability: dict of time, matrix

    def recv_data(self, sock: socket.socket):
        sock.recv(1024)  # should be empty
        message = self.prepend_header(self.header_fmt, self.state.to_json())
        sock.sendall(message)

    def send_data(self, sock: socket.socket):
        pass

    def process(self, **kwargs):
        while not self.halt:
            # FIXME update state
            self.tick += 1
            time.sleep(1)


if __name__ == '__main__':
    Simulator('config.cfg').run(8888)  # FIXME create config
