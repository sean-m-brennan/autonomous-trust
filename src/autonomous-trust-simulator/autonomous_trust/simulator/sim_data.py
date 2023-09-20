from datetime import datetime
from typing import Optional

from autonomous_trust.core.config import Configuration
from autonomous_trust.inspector.peer.position import Position, GeoPosition
from .peer.peer import PeerInfo


Matrix = dict[str, dict[str, bool]]


Map = dict[str, Position]


class SimState(Configuration):
    """Communicates sim state snapshot"""
    def __init__(self, time: Optional[datetime] = None, center: Optional[GeoPosition] = None,
                 scale: Optional[float] = None, peers: Optional[Map] = None, reachable: Optional[Matrix] = None,
                 blank: bool = False):
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
        self.blank = blank

    def convert(self) -> 'SimState':
        state = SimState(**self.to_dict())
        for peer_id in state.peers:
            state.peers[peer_id] = state.peers[peer_id].convert(GeoPosition)
        return state


class SimConfig(Configuration):
    """Just the sim scenario"""
    def __init__(self, **kwargs):
        super().__init__()
        self.time: datetime = kwargs['time']
        self.peers: list[PeerInfo] = kwargs['peers']

    @classmethod
    def load(cls, data: str) -> 'SimConfig':
        return cls.from_yaml_string(data)
