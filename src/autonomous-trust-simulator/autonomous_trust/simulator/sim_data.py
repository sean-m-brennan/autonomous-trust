from datetime import datetime
from typing import Optional, Any

from autonomous_trust.core.config import Configuration
from .peer.position import Position, GeoPosition
from .peer.peer import PeerData


Matrix = dict[str, dict[str, bool]]


Map = dict[str, Position]


class SimState(Configuration):
    """Communicates sim state snapshot"""
    def __init__(self, time: Optional[datetime] = None, center: Optional[GeoPosition] = None,
                 scale: Optional[float] = None, peers: Optional[Map] = None, reachable: Optional[Matrix] = None):
        super().__init__()
        self.time = time
        if time is None:
            self.time = datetime.now()
        self.center = center
        self.scale = scale
        self.peers = peers
        if peers is None:
            self.peers: Map = {}
        self.reachable = reachable
        if reachable is None:
            self.reachable: Matrix = {}


class SimConfig(Configuration):
    """Just the scenario"""
    def __init__(self, **kwargs):
        super().__init__()
        self.time: datetime = kwargs['time']
        self.peers: list[PeerData] = kwargs['peers']

    @classmethod
    def load(cls, data: str) -> 'SimConfig':
        return cls.from_yaml_string(data)

