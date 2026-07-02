# ******************
#  Copyright 2023 TekFive, Inc., Sean M. Brennan, and contributors
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
# ******************

import os
import sys
from datetime import UTC, datetime
from queue import Empty, Full

from autonomous_trust.core import Process, ProcMeta, CfgIds, Configuration, InitializableConfig
from autonomous_trust.core.identity import Identity
from autonomous_trust.core.network import Message
from autonomous_trust.core.protocol import Protocol
from autonomous_trust.core.protobuf.services import metadata_pb2
from .position import Position


class PeerData(Configuration):
    def __init__(self, time, position, speed, kind, data_type, data_channels):
        super().__init__(metadata_pb2.PeerData)
        self.time = time
        self.position = position
        self.speed = speed
        self.kind = kind
        self.data_type = data_type
        self.data_channels = data_channels


class MetadataProtocol(Protocol):
    request = 'request'
    metadata = 'metadata'


class TimeSource(object):
    def acquire(self) -> datetime:
        """Return the current time, NTP-adjusted when a sync is running.

        Delegates to the core time authority
        (``autonomous_trust.core.system.now``), which adds the running NTP
        offset maintained by ``core/network/ntp.py`` (the Python mirror of the
        C-side native RFC 5905 client at ``network/ntp.c``). With no NTP sync
        active the offset is zero, so this is identical to ``datetime.now(UTC)``;
        but once a peer-shared time source is syncing, all participants order
        events on a common clock despite local drift. See ``NtpTimeSource`` to
        drive that sync from the metadata config.
        """
        try:
            from autonomous_trust.core.system import now
            return now()
        except ImportError:  # core time authority unavailable — local fallback
            return datetime.now(UTC)


class NtpTimeSource(TimeSource):
    """Time source that also drives a background NTP sync.

    Constructing one ensures a daemon thread is querying ``server`` every
    ``interval`` seconds and maintaining the process-global offset that
    ``TimeSource.acquire`` (inherited) then applies. The sync is started at
    most once per ``(server, interval)`` pair, so repeated construction — e.g.
    on every config reload — never spawns duplicate threads. If NTP is
    unavailable (no ``ntplib``, no reachable server) the offset stays zero and
    ``acquire`` degrades to the local UTC clock.

    This is the parameterized counterpart enabled by ``Metadata``'s per-source
    kwargs payload: register it as a metadata class and give the metadata a
    ``time_src_kwargs`` of e.g. ``{'server': 'ntp.mil', 'interval': 60}``.
    """

    _started: set = set()

    def __init__(self, server: str = 'pool.ntp.org', interval: float = 300.0):
        self.server = server
        self.interval = float(interval)
        key = (self.server, self.interval)
        if key in NtpTimeSource._started:
            return
        try:
            from autonomous_trust.core.network.ntp import start_sync
            start_sync(self.server, self.interval)
            NtpTimeSource._started.add(key)
        except ImportError:  # NTP support absent — acquire() falls back to local clock
            pass


class PositionSource(object):
    def acquire(self) -> tuple[Position, float]:
        raise NotImplementedError


_ALLOWED_METADATA_CLASSES = {
    'autonomous_trust.services.peer.metadata.TimeSource',
    'autonomous_trust.services.peer.metadata.NtpTimeSource',
    'autonomous_trust.services.peer.metadata.PositionSource',
    'autonomous_trust.services.peer.position.Position',
    'autonomous_trust.services.peer.position.GeoPosition',
    'autonomous_trust.services.peer.position.UTMPosition',
}


class Metadata(InitializableConfig):
    def __init__(self, uuid: str, peer_kind: str, data_meta: dict[str, int],
                 position_src_class: type, time_src_class: type = None,
                 position_src_kwargs: dict = None, time_src_kwargs: dict = None):
        self.uuid = uuid
        self.peer_kind = peer_kind
        self.data_meta = data_meta
        self.position_src_class = self.class_to_name(position_src_class)
        if time_src_class is None:
            self.time_src_class = self.class_to_name(TimeSource)
        else:
            self.time_src_class = self.class_to_name(time_src_class)
        # Constructor params for the source classes. These serialize with the
        # rest of the config (plain dicts of scalars) and are passed through by
        # the source properties, so a registered source may be parameterized
        # (e.g. a GPS device path / GeoPosition origin for the position source,
        # or an NTP server/interval for NtpTimeSource) instead of being limited
        # to a no-arg __init__.
        self.position_src_kwargs = dict(position_src_kwargs) if position_src_kwargs else {}
        self.time_src_kwargs = dict(time_src_kwargs) if time_src_kwargs else {}

    @property
    def position_source(self):
        return self.name_to_class(self.position_src_class)(**(self.position_src_kwargs or {}))

    @property
    def time_source(self):
        return self.name_to_class(self.time_src_class)(**(self.time_src_kwargs or {}))

    @classmethod
    def register_metadata_class(cls, klass):
        _ALLOWED_METADATA_CLASSES.add(klass.__module__ + '.' + klass.__qualname__)

    @classmethod
    def name_to_class(cls, qual_name):
        if qual_name not in _ALLOWED_METADATA_CLASSES:
            raise ValueError(f"Class '{qual_name}' not in allowed metadata classes")
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
        cfg_file = os.path.join(Configuration.get_cfg_dir(), CfgIds.identity + Configuration.file_ext)
        return Identity.from_file(cfg_file)

    @classmethod
    def initialize(cls, peer_kind: str, data_meta: dict[str, int],
                   position_source: type, time_source: type = None,
                   position_src_kwargs: dict = None, time_src_kwargs: dict = None):
        uuid = cls.get_assoc_ident().uuid
        return Metadata(uuid, peer_kind, data_meta, position_source, time_source,
                        position_src_kwargs, time_src_kwargs)


class MetadataSource(Process, metaclass=ProcMeta,
                     proc_name='metadata-source', description='Peer metadata service'):
    def __init__(self, configurations, subsystems, log_queue, dependencies, **kwargs):
        super().__init__(configurations, subsystems, log_queue, dependencies=dependencies)
        self.cfg = configurations[self.name]
        self.protocol = MetadataProtocol(self.name, self.logger, configurations)
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
            position, speed = self.cfg.position_source.acquire()
            obj = PeerData(time, position, speed, self.cfg.peer_kind,
                           self.cfg.data_type, self.cfg.data_channels).to_string()
            for peer in self.clients:
                msg = Message(self.name, MetadataProtocol.metadata, obj, peer)
                try:
                    queues[CfgIds.network].put(msg, block=True, timeout=self.q_cadence)
                except Full:
                    self.logger.warning("Queue full, dropping metadata message for %s", peer)

            self.sleep_until(self.cadence)
