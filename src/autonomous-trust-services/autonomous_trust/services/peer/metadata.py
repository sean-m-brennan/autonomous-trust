import os
import sys
from datetime import datetime
from queue import Empty, Full

from autonomous_trust.core import Process, ProcMeta, CfgIds, Configuration, InitializableConfig
from autonomous_trust.core.identity import Identity
from autonomous_trust.core.network import Message
from autonomous_trust.core.protocol import Protocol
from .position import Position


class PeerData(Configuration):
    def __init__(self, time, position, kind, data_type, data_channels):
        self.time = time
        self.position = position
        self.kind = kind
        self.data_type = data_type
        self.data_channels = data_channels


class MetadataProtocol(Protocol):
    request = 'request'
    metadata = 'metadata'


class TimeSource(object):
    def acquire(self) -> datetime:
        # TODO tap into custom NTP
        return datetime.utcnow()


class PositionSource(object):
    def acquire(self) -> Position:
        raise NotImplementedError


class Metadata(InitializableConfig):
    def __init__(self, uuid, peer_kind, data_type, data_channels, position_src_class, time_src_class=None):
        self.uuid = uuid
        self.peer_kind = peer_kind
        self.data_type = data_type
        self.data_channels = data_channels
        self.position_src_class = self.class_to_name(position_src_class)
        if time_src_class is None:
            self.time_src_class = self.class_to_name(TimeSource)
        else:
            self.time_src_class = self.class_to_name(time_src_class)

    @property
    def position_source(self):
        return self.name_to_class(self.position_src_class)()  # TODO params?

    @property
    def time_source(self):
        return self.name_to_class(self.time_src_class)()

    @classmethod
    def name_to_class(cls, qual_name):
        mod, klass = qual_name.rsplit('.', 1)
        return getattr(sys.modules[mod], klass)

    @classmethod
    def class_to_name(cls, klass: type):
        if isinstance(klass, str):
            return klass
        return klass.__module__ + '.' + klass.__qualname__

    @staticmethod
    def get_assoc_ident() -> Identity:
        # Assumes root dir is set properly
        cfg_file = os.path.join(Configuration.get_cfg_dir(), CfgIds.identity + Configuration.yaml_file_ext)
        return Identity.from_file(cfg_file)

    @classmethod
    def initialize(cls, peer_kind: str, data_type: str, data_channels: int,
                   position_source: PositionSource, time_source: TimeSource = None):
        uuid = cls.get_assoc_ident().uuid
        return Metadata(uuid, peer_kind, data_type, data_channels, position_source, time_source)


class MetadataSource(Process, metaclass=ProcMeta,
                     proc_name='metadata-source', description='Peer metadata service'):
    def __init__(self, configurations, subsystems, log_queue, dependencies, **kwargs):
        super().__init__(configurations, subsystems, log_queue, dependencies=dependencies)
        self.cfg = configurations[self.name]
        self.protocol = MetadataProtocol(self.name, self.logger, configurations[CfgIds.peers])
        self.protocol.register_handler(MetadataProtocol.request, self.handle_requests)
        self.clients: dict[str, tuple[bool, str, Identity]] = {}

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

            time = self.cfg.time_source.acquire()
            position = self.cfg.position_source.acquire()
            obj = PeerData(time, position, self.cfg.peer_kind,
                           self.cfg.data_type, self.cfg.data_channels).to_yaml_string()
            for peer in self.clients:
                msg = Message('daq', MetadataProtocol.metadata, obj, peer)
                try:
                    queues[CfgIds.network].put(msg, block=True, timeout=self.q_cadence)
                except Full:
                    pass

            self.sleep_until(self.cadence)
