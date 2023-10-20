import logging
import sys
from datetime import datetime, timedelta
from queue import Empty

from autonomous_trust.core import Process, ProcMeta, CfgIds, from_yaml_string, QueueType
from autonomous_trust.core.automate import create_queue
from autonomous_trust.core.identity import Peers, Identity
from autonomous_trust.core.network import Message
from autonomous_trust.core.protocol import Protocol
from autonomous_trust.core.reputation import ReputationProtocol
from autonomous_trust.services.network_statistics import NetworkStats, NetStatsProtocol, NetStatsSource
from autonomous_trust.services.peer.metadata import MetadataProtocol, MetadataSource, PeerData
from autonomous_trust.services.peer.position import Position, GeoPosition


NullPeerData = lambda: PeerData(datetime.utcfromtimestamp(0), Position(0, 0), '')  # noqa


class PeerDataAcq(object):
    """Peer acquired-data store"""
    def __init__(self, uuid: str, ident: Identity, metadata: PeerData, cohort: 'CohortInterface',
                 video_stream: QueueType, data_stream: QueueType):
        self._uuid = uuid
        self._ident = ident
        self.metadata = metadata
        self.cohort = cohort
        self.video_stream = video_stream
        self.data_stream = data_stream
        self.network_history: dict[str, list[NetworkStats]] = {}
        self.reputation = 0.

    @property
    def tick(self):
        return self.cohort.tick

    @property
    def time(self):
        return self.metadata.time

    @property
    def position(self):
        return self.metadata.position

    @property
    def kind(self):
        return self.metadata.kind

    @property
    def others(self):
        return self.network_history.keys()

    @property
    def name(self):
        return self._ident.fullname

    @property
    def nickname(self):
        return self._ident.nickname

    @property
    def uuid(self):
        return self._uuid

    @property
    def identity(self):
        return self._ident


class CohortInterface(object):
    def __init__(self, log_level: int = logging.INFO, logfile: str = None):
        self.tick = 0
        self.paused = False
        self.peers: dict[str, PeerDataAcq] = {}
        self._time: datetime = datetime.now()
        self._center = GeoPosition(0, 0)

        self.log_level = log_level
        self.logfile = logfile
        if logfile is None:
            handler = logging.StreamHandler(sys.stdout)
        else:
            handler = logging.FileHandler(logfile)
        prefix = self.__class__.__name__ + ' '
        handler.setFormatter(logging.Formatter(prefix + '%(asctime)s.%(msecs)03d - %(levelname)s %(message)s',
                                               '%Y-%m-%d %H:%M:%S'))
        handler.setLevel(log_level)
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.addHandler(handler)
        self.logger.setLevel(log_level)

    @property
    def center(self) -> Position:
        return self._center

    @property
    def time(self) -> datetime:
        return self._time

    def update(self):
        raise NotImplementedError


class Cohort(CohortInterface):
    epoch = datetime(1970, 1, 1)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def update(self):
        pass

    def update_group(self, group_ids: dict[str, Identity]):
        for uuid in group_ids:
            if uuid not in self.peers:
                self.peers[uuid] = PeerDataAcq(uuid, group_ids[uuid], NullPeerData(), self,
                                               create_queue(), create_queue())
                # FIXME dynamically creating queues is a problem: "Pickling an AuthenticationString object is disallowed for security reasons"
        for uuid in self.peers:
            if uuid not in group_ids:
                del self.peers[uuid]

    @property
    def center(self) -> Position:
        positions = []
        for uuid in self.peers:
            positions.append(self.peers[uuid].position.convert(GeoPosition))
        return GeoPosition.middle(positions)

    @property
    def time(self) -> datetime:
        times = []
        for uuid in self.peers:
            times.append(self.peers[uuid].time - self.epoch)
        if len(times) < 1:
            return self.epoch
        return self.epoch + sum(times, timedelta()) / len(times)


class CohortProtocol(Protocol):
    meta = 'meta'
    stats = 'stats'


class CohortTracker(Process, metaclass=ProcMeta,
                    proc_name='daq', description='Clearinghouse for peer data acquisition'):
    def __init__(self, configurations, subsystems, log_queue, dependencies, **kwargs):
        super().__init__(configurations, subsystems, log_queue, dependencies=dependencies)
        self.cohort: Cohort = kwargs.get('cohort')
        self.protocol = CohortProtocol(self.name, self.logger, configurations[CfgIds.peers])
        self.protocol.register_handler(CohortProtocol.meta, self.handle_metadata)
        self.protocol.register_handler(CohortProtocol.stats, self.handle_stats)
        self.servicers = []

    def handle_metadata(self, _, message):
        if message.function == CohortProtocol.meta:
            metadata = from_yaml_string(message.obj)
            uuid = message.from_whom.uuid
            if uuid in self.cohort.peers:
                peer = self.cohort.peers[uuid]
                peer.metadata = metadata
            return True
        return False

    def handle_stats(self, _, message):
        if message.function == CohortProtocol.stats:
            data = from_yaml_string(message.obj)  # FIXME 'total' also
            uuid = message.from_whom.uuid
            if uuid in self.cohort.peers:
                peer = self.cohort.peers[uuid]
                for uuid in data:
                    peer.network_history[uuid].append(data[uuid])
            return True
        return False

    def process(self, queues, signal):
        while self.keep_running(signal):
            if 'peer-metadata' in self.protocol.peer_capabilities:
                for peer in self.protocol.peer_capabilities['peer-metadata']:
                    if peer not in self.servicers:
                        self.servicers.append(peer)
                        msg = Message(MetadataSource.name, MetadataProtocol.request, True, peer)
                        queues[CfgIds.network].put(msg, block=True, timeout=self.q_cadence)
                        msg = Message(NetStatsSource.name, NetStatsProtocol.request, True, peer)
                        queues[CfgIds.network].put(msg, block=True, timeout=self.q_cadence)

            try:
                message = queues[self.name].get(block=True, timeout=self.q_cadence)
            except Empty:
                message = None
            if message:
                if isinstance(message, Message) and message.function == ReputationProtocol.rep_resp:
                    rep = message.obj
                    if rep.peer_id in self.cohort.peers:
                        peer = self.cohort.peers[rep.peer_id]
                        peer.reputation = rep.score
                elif isinstance(message, Peers):
                    peer_idents = {p.uuid: p for p in message.listing.values()}
                    self.cohort.update_group(peer_idents)
                elif not self.protocol.run_message_handlers(queues, message):
                    if isinstance(message, Message):
                        self.logger.error('Unhandled message %s' % message.function)
                    else:
                        self.logger.error('Unhandled message of type %s' % message.__class__.__name__)  # noqa

            self.sleep_until(self.cadence)
