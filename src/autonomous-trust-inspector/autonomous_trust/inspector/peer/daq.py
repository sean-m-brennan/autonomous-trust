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

import logging
import sys
from collections import deque
from datetime import datetime, timedelta, timezone
from queue import Empty, Queue
from typing import Callable, Union

from autonomous_trust.core import Process, ProcMeta, CfgIds, from_json_string, QueueType
from autonomous_trust.core.automate import QueuePool
from autonomous_trust.core.identity import Peers, Identity
from autonomous_trust.core.network import Message
from autonomous_trust.core.protocol import Protocol
from autonomous_trust.core.reputation import ReputationProtocol
from autonomous_trust.services.network_statistics import NetworkStats, NetStatsProtocol, NetStatsSource
from autonomous_trust.services.peer.metadata import MetadataProtocol, MetadataSource, PeerData
from autonomous_trust.services.peer.position import Position, GeoPosition


NullPeerData = lambda: PeerData(datetime.fromtimestamp(0, timezone.utc), Position(0, 0), 0., '', '', 0)  # noqa

StreamType = Union[QueueType, deque]


class PeerDataAcq(object):
    """Peer acquired-data store"""
    max_history = 20

    def __init__(self, uuid: str, index: int, ident: Identity, metadata: PeerData, cohort: 'CohortInterface',
                 video_stream: StreamType, data_stream: StreamType):
        self._uuid = uuid
        self.index = index
        self._ident = ident
        self.metadata = metadata
        self.cohort = cohort
        self.video_stream = video_stream
        self.data_stream = data_stream
        self.active = False
        self.network_history: dict[str, deque[NetworkStats]] = {}
        self.total_network_history: deque[NetworkStats] = deque(maxlen=self.max_history)
        self.reputation_history: deque[float] = deque(maxlen=self.max_history)
        # Per-other (transitive) trust: THIS peer's reputation of each other
        # peer, keyed by the other's uuid. Populated from peer-pair rep_resp
        # (§4.2:159) so the per-other trust gauges are precise rather than the
        # aggregate stand-in.
        self.reputation_by_other: dict[str, deque[float]] = {}

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
        return self._ident.nickname  # Zooko online name (was fullname)

    @property
    def nickname(self):
        return self._ident.petname  # Zooko local display name

    @property
    def uuid(self):
        return self._uuid

    @property
    def identity(self):
        return self._ident

    def record_reputation_of(self, other_uuid: str, score: float):
        """Record this peer's reputation of ``other_uuid`` (per-other trust)."""
        self.reputation_by_other.setdefault(
            other_uuid, deque(maxlen=self.max_history)).append(score)

    def reputation_of(self, other_uuid: str):
        """Latest reputation this peer assigns to ``other_uuid``, or None if this
        peer has no recorded view of that other."""
        hist = self.reputation_by_other.get(other_uuid)
        return hist[-1] if hist else None


class CohortInterface(object):
    def __init__(self, log_level: int = logging.INFO, logfile: str = None):
        self.paused = True  # always start in paused state
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
        self.updaters: list[Callable[[], None]] = []
        self.browser_connected = 0

    @property
    def center(self) -> Position:
        return self._center

    @property
    def time(self) -> datetime:
        return self._time

    def register_updater(self, updater: Callable[[], None]):
        self.updaters.append(updater)

    def deregister_updater(self, updater: Callable[[], None]):
        self.updaters.remove(updater)

    def update(self, initial: bool = False):
        if initial:
            self.acquire_data()
        elif self.browser_connected > 0 and not self.paused:
            self.acquire_data()
            for updater in self.updaters:
                updater()

    def acquire_data(self):
        raise NotImplementedError

    def start(self):
        raise NotImplementedError

    def stop(self):
        raise NotImplementedError


class Cohort(CohortInterface):
    epoch = datetime(1970, 1, 1)

    def __init__(self, queue_pool: QueuePool, **kwargs):
        super().__init__(**kwargs)
        self.queue_pool = queue_pool

    def start(self):
        pass

    def acquire_data(self):
        # Feature gap (open): implement live data acquisition by
        # draining each peer's data queue (allocated from
        # self.queue_pool in update_group) into the matching
        # PeerDataAcq. The warning log keeps the no-op visible at
        # runtime; without this, downstream renderers stay empty.
        self.logger.warning('Cohort.acquire_data is not yet implemented; no live data will be collected')

    def update_group(self, group_ids: dict[str, Identity]):
        # Known limitation (documented as deferred for security reasons):
        # Each new peer consumes two pre-allocated queues from
        # `self.queue_pool` rather than creating fresh ones. Spawning
        # multiprocessing.Queue objects after the daemon parent has
        # forked workers triggers Python's
        # "Pickling an AuthenticationString object is disallowed for
        # security reasons" — an intentional CPython mitigation that
        # prevents cross-process credential leakage. The pool is sized
        # to MAX_PEERS at startup; if a deployment exceeds it the right
        # fix is enlarging the pool, not dynamic creation.
        for idx, uuid in enumerate(group_ids):
            if uuid not in self.peers:
                self.peers[uuid] = PeerDataAcq(uuid, idx, group_ids[uuid], NullPeerData(), self,
                                               self.queue_pool.next(), self.queue_pool.next())
        to_remove = [uuid for uuid in self.peers if uuid not in group_ids]
        for uuid in to_remove:
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
        self.protocol = CohortProtocol(self.name, self.logger, configurations)
        self.protocol.register_handler(CohortProtocol.meta, self.handle_metadata)
        self.protocol.register_handler(CohortProtocol.stats, self.handle_stats)
        self.servicers = []

    def handle_metadata(self, _, message):
        if message.function == CohortProtocol.meta:
            metadata = from_json_string(message.obj)
            uuid = message.from_whom.uuid
            if uuid in self.cohort.peers:
                peer = self.cohort.peers[uuid]
                peer.metadata = metadata
            return True
        return False

    def handle_stats(self, _, message):
        if message.function == CohortProtocol.stats:
            data = from_json_string(message.obj)
            uuid = message.from_whom.uuid
            if uuid in self.cohort.peers:
                peer = self.cohort.peers[uuid]
                total = data.pop('total', None)
                if total is not None:
                    peer.total_network_history.append(total)
                for peer_uuid in data:
                    # network_history is a plain dict; create the per-other deque
                    # on first sight of a peer_uuid (bounded like the others),
                    # otherwise the first stat for a new other raises KeyError.
                    peer.network_history.setdefault(
                        peer_uuid, deque(maxlen=PeerDataAcq.max_history)).append(data[peer_uuid])
            return True
        return False

    def handle_reputation(self, message):
        """Record a reputation response into the peer's reputation_history.

        Returns True if the message was a reputation response (i.e. consumed
        here), False otherwise so the caller can try other dispatch. Appends to
        the history the renderers actually read (peer_status micrograph + the
        per-other trust-gauge stand-in); the former inline `peer.reputation =
        rep.score` set an attribute no renderer consumes, leaving the history
        permanently empty.
        """
        if not (isinstance(message, Message) and message.function == ReputationProtocol.rep_resp):
            return False
        rep = message.obj
        subject = rep.peer_id
        # Direct view: append to the subject's aggregate history (what the
        # micrograph + the fallback trust-gauge read).
        if subject in self.cohort.peers:
            self.cohort.peers[subject].reputation_history.append(rep.score)
        # Transitive view (§4.2:159): a rep_resp routed back from a peer
        # (observer != subject) is THAT observer's opinion of the subject —
        # record it as the observer's per-other reputation of the subject.
        observer = getattr(getattr(message, 'from_whom', None), 'uuid', None)
        if observer is not None and observer != subject and observer in self.cohort.peers:
            self.cohort.peers[observer].record_reputation_of(subject, rep.score)
        return True

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
                if self.handle_reputation(message):
                    pass
                elif isinstance(message, Peers):
                    peer_idents = {p.uuid: p for p in message.listing.values()}
                    self.cohort.update_group(peer_idents)
                elif not self.protocol.run_message_handlers(queues, message):
                    if isinstance(message, Message):
                        self.logger.error(f'Unhandled message {message.function}')
                    else:
                        self.logger.error(f'Unhandled message of type {message.__class__.__name__}')  # noqa

            self.sleep_until(self.cadence)
