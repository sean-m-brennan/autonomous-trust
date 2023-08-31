import json

from .util import Serializable
from .peer.position import Position
from .peer.peer import PeerConnection, PeerData


Matrix = dict[str, dict[str, bool]]


Map = dict[str, Position]


class SimState(Serializable):
    """Communicates sim state snapshot"""
    def __init__(self, peers: dict[str, PeerConnection] = None, reachable: Matrix = None):
        self.peers = peers
        if peers is None:
            self.peers: dict[str, PeerConnection] = {}
        self.reachable = reachable
        if reachable is None:
            self.reachable: Matrix = {}


class SimConfig(Serializable):
    """Just the scenario"""
    def __init__(self, **kwargs):
        self.peers: list[PeerData] = kwargs['peers']

    @classmethod
    def load(cls, data):
        return SimConfig(**(json.loads(data)))


