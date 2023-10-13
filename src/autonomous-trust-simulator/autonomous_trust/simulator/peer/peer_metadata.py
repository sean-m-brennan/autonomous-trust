import threading
from datetime import datetime
from typing import Optional

from autonomous_trust.core import ProcMeta
from autonomous_trust.services.peer.metadata import MetadataSource, PositionSource, TimeSource, Metadata
from autonomous_trust.services.peer.position import Position
from .. import default_port
from ..sim_client import SimClient
from ..sim_data import SimState


class PositionSimSource(PositionSource):
    def __init__(self):
        super().__init__()
        self.position: Optional[Position] = None

    def acquire(self) -> Position:
        return self.position


class TimeSimSource(TimeSource):
    def __init__(self):
        super().__init__()
        self.time: datetime = datetime.now()

    def acquire(self) -> datetime:
        return self.time


class SimMetadata(Metadata):
    def __init__(self, host, port=default_port, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.host = host
        self.port = port

    @classmethod
    def initialize(cls, type_of_peer: str, sim_host: str, sim_port: int = default_port, data_type: str = None, data_channels: int = 0):
        uuid = cls.get_assoc_ident().uuid
        return SimMetadata(sim_host, sim_port, uuid, type_of_peer, data_type, data_channels,
                           PositionSimSource, TimeSimSource)


class SimMetadataSource(MetadataSource, metaclass=ProcMeta,
                        proc_name='metadata-source', description='Peer metadata service'):
    def __init__(self, configurations, subsystems, log_queue, dependencies):
        super().__init__(configurations, subsystems, log_queue, dependencies=dependencies)
        self.sim = SimClient(self.sim_callback)
        thread = threading.Thread(target=self.sim.run, args=(self.cfg.host, self.cfg.port))
        thread.start()

    def sim_callback(self, state: SimState):
        self.cfg.position_source.position = state.peers[self.cfg.uuid]
        self.cfg.time_source.time = state.time
