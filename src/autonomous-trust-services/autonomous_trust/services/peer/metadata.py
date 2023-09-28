from datetime import datetime
from queue import Empty, Full

from autonomous_trust.core import Process, ProcMeta, CfgIds, Configuration
from autonomous_trust.core.identity import Identity
from autonomous_trust.core.network import Message
from autonomous_trust.core.protocol import Protocol
from .position import Position


class PeerData(Configuration):
    def __init__(self, time, position, kind):
        self.time = time
        self.position = position
        self.kind = kind


class MetadataProtocol(Protocol):
    request = 'request'
    metadata = 'metadata'


class TimeSource(object):
    def acquire(self) -> datetime:
        return datetime.utcnow()


class PositionSource(object):
    def acquire(self) -> Position:
        raise NotImplementedError


class MetadataSource(Process, metaclass=ProcMeta,
                     proc_name='metadata-source', description='Peer metadata service'):
    def __init__(self, configurations, subsystems, log_queue, dependencies, **kwargs):
        super().__init__(configurations, subsystems, log_queue, dependencies=dependencies)
        self.protocol = MetadataProtocol(self.name, self.logger, configurations[CfgIds.peers])
        self.protocol.register_handler(MetadataProtocol.request, self.handle_requests)
        self.clients: dict[str, tuple[bool, str, Identity]] = {}
        self.kind = kwargs['peer_kind']
        self.position_source = kwargs['position_source']  # FIXME data source
        self.time_source = kwargs.get('time_source', TimeSource())

    def handle_requests(self, _, message):
        if message.function == MetadataProtocol.request:
            uuid = message.from_whom.uuid
            if uuid not in self.clients:
                self.clients[uuid] = message.from_whom
            return True
        return False

    def process(self, queues, signal):
        while self.keep_running(signal):
            try:
                message = queues[self.name].get(block=True, timeout=self.q_cadence)
            except Empty:
                message = None
            if message:
                if not self.protocol.run_message_handlers(queues, message):
                    if isinstance(message, Message):
                        self.logger.error('Unhandled message %s' % message.function)
                    else:
                        self.logger.error('Unhandled message of type %s' % message.__class__.__name__)  # noqa

            time = self.time_source.acquire()
            position = self.position_source.acquire()
            obj = PeerData(time, position, self.kind).to_yaml_string()
            for peer in self.clients:
                msg = Message('daq', MetadataProtocol.metadata, obj, peer)
                try:
                    queues[CfgIds.network].put(msg, block=True, timeout=self.q_cadence)
                except Full:
                    pass

            self.sleep_until(self.cadence)
