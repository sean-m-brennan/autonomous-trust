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
import threading
import time
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

#: Poll interval for the deque form of a peer stream. A deque has no blocking
#: API, so that path has to poll; it is short because it bounds LATENCY, and it
#: exists only for in-process/test streams. The Queue form -- what production
#: actually supplies, from QueuePool -- blocks in the kernel and never polls.
DEQUE_POLL_SEC = 0.005

#: The deque-poll sleep, bound to its own name purely so a test can observe
#: THIS call site. Patching `time.sleep` instead is process-wide: every other
#: thread that happens to sleep during the window -- the Cohort tick loop at
#: the bottom of this same module, for one -- is then indistinguishable from a
#: poll here, which is exactly how a leaked tick thread once made
#: `test_a_queue_wait_times_out_without_polling` fail at random. Rebinding
#: `daq.time` would not separate them either; both look `time` up in these same
#: globals. Call it, do not inline `time.sleep`, or the seam is lost.
_poll_sleep = time.sleep


def stream_take(stream: StreamType, timeout: float):
    """Take one item from a peer stream, waiting up to ``timeout`` seconds.

    Raises :class:`queue.Empty` if nothing arrives in time.

    A Queue is waited on with a blocking ``get``, so a 30 fps source is not
    throttled by a poll interval and an idle feed costs no wakeups. The previous
    `while len(stream) < 1: sleep(0.1)` did both: it capped throughput at 10 fps,
    added up to 100 ms of latency per frame, and spun the whole time. It also
    could not work at all against the Queue production supplies -- a Queue proxy
    has neither ``__len__`` nor ``pop``.
    """
    get = getattr(stream, 'get', None)
    if get is not None:
        return get(block=True, timeout=timeout)
    # deque: no blocking API, so poll briefly
    deadline = time.monotonic() + timeout
    while True:
        try:
            return stream.pop()
        except IndexError:
            if time.monotonic() >= deadline:
                raise Empty
            _poll_sleep(DEQUE_POLL_SEC)


def stream_take_latest(stream: StreamType, timeout: float):
    """Like :func:`stream_take`, then discard any backlog and keep the newest.

    For a live view a stale frame is worth less than the current one, so falling
    behind must not turn into a growing lag. The deque form got this for free
    (``pop()`` takes the newest); a Queue is FIFO, so the backlog is drained
    explicitly. Returns the newest item available at this moment.
    """
    item = stream_take(stream, timeout)
    get = getattr(stream, 'get_nowait', None)
    if get is None:
        # A deque's pop() already took the NEWEST item, so draining further
        # would walk backwards into older frames. Older entries are left where
        # they are, exactly as the original pop()-based loop left them.
        return item
    while True:
        try:
            item = get()
        except Empty:
            return item


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
        # `active` drives the feeds, so its changes are worth waking them for
        # rather than making them poll. Event-backed via the property below;
        # every existing `peer.active = x` call site keeps working.
        self._active = False
        self._active_event = threading.Event()
        self.network_history: dict[str, deque[NetworkStats]] = {}
        self.total_network_history: deque[NetworkStats] = deque(maxlen=self.max_history)
        self.reputation_history: deque[float] = deque(maxlen=self.max_history)
        # Per-other (transitive) trust: THIS peer's reputation of each other
        # peer, keyed by the other's uuid. Populated from peer-pair rep_resp
        # so the per-other trust gauges are precise rather than the
        # aggregate stand-in.
        self.reputation_by_other: dict[str, deque[float]] = {}

    @property
    def active(self):
        return self._active

    @active.setter
    def active(self, value):
        self._active = bool(value)
        if self._active:
            self._active_event.set()
        else:
            self._active_event.clear()

    def wait_active(self, timeout: float) -> bool:
        """Block until this peer is active, or ``timeout`` elapses.

        Returns its state on waking. Opening a detail drawer therefore starts the
        feed at once instead of up to one poll interval later, and an idle feed
        waits instead of spinning.
        """
        return self._active_event.wait(timeout)

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
        # Loggers are singletons keyed by name, so a second instance of this
        # class in the same process would otherwise ADD a second handler and
        # every line would print twice -- N instances, N copies of each line
        # (a full test session made one error appear 25 times). Same guard, and
        # the same reason, as Automate's in core/_python/automate.py.
        self.logger.handlers.clear()
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
                try:
                    updater()
                except Exception as err:
                    # One component must not silence the rest of the dashboard.
                    # This was a bare loop, and `CohortInterface.time` raised on
                    # every tick (naive epoch vs tz-aware peer times), so the
                    # timer -- registered before the map and the peer panels --
                    # took every updater after it down with it and the whole UI
                    # sat frozen. Named, because 'the dashboard is stale' with
                    # nothing in the log is the hardest kind of outage to place.
                    self.logger.error('Updater %s failed: %s', getattr(updater, '__qualname__', updater), err)

    def acquire_data(self):
        raise NotImplementedError

    def start(self):
        raise NotImplementedError

    def stop(self):
        raise NotImplementedError


class Cohort(CohortInterface):
    """Peer store shared, by message, between the DAQ worker and the UI.

    **The memory model, because it decides the whole design.** One Cohort is
    constructed in the parent and handed to `CohortTracker`, the video/data
    receivers AND the UI; the workers are then pickled into forked processes. So
    `self.peers` — a plain dict — is a SEPARATE dict per process. Whatever
    `CohortTracker` records in its worker (roster, metadata, network stats,
    reputation) is invisible to the UI, which is why the UI rendered nothing.
    Measured, not assumed: a worker writing `peers['x']` leaves the parent's dict
    empty, while a queue drawn from `queue_pool` carries a value across fine.

    What DOES cross is the pooled queues: they are `manager.Queue` proxies built
    before any fork. So peer STATE travels as messages over one of those queues —
    `CohortTracker` publishes deltas from its worker, and :meth:`acquire_data`
    applies them in the UI process on every tick. The per-peer video/data streams
    are untouched by this: those queues belong to `VideoFeed`/`DataFeed`, which
    consume them directly, and draining them here would starve the feeds.

    Queue ASSIGNMENT travels the same way, by slot index. Each process has its
    own `in_use` flags, so two processes calling `QueuePool.next()` agree only by
    accident; the owner reserves an index and publishes it, and everyone else
    resolves it with `QueuePool.slot()`.
    """
    #: UTC-AWARE deliberately. Peer times are aware -- `TimeSource.acquire`
    #: returns UTC and a decoded `PeerData.time` carries a tzinfo -- so a naive
    #: epoch made every `time` subtraction raise TypeError, for real peers as
    #: much as for placeholders.
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)

    #: Ceiling on deltas applied per UI tick. A burst must not stall the render
    #: loop; whatever is left is applied on the next tick.
    max_updates_per_tick = 256

    #: The renderer's subscription name; the default consumer for acquire_data.
    UI_CONSUMER = 'ui'

    def __init__(self, queue_pool: QueuePool, **kwargs):
        super().__init__(**kwargs)
        self.queue_pool = queue_pool
        # consumer name -> slot index. A queue has exactly ONE consumer, so each
        # process that needs the state gets its own channel and the publisher
        # fans out to all of them. Populated in the PARENT (the UI here, each
        # receiver from its own __init__, which also runs pre-fork), so every
        # forked copy inherits the full subscriber list.
        self._subscriptions: dict[str, int] = {}
        self._dropped_updates = 0
        self.subscribe(self.UI_CONSUMER)
        # Owner-side record of what was assigned to whom, so a roster delta can
        # restate the whole assignment rather than only the change.
        self._peer_slots: dict[str, tuple] = {}
        self._tick_thread = None
        self._halt = False

    def subscribe(self, name: str):
        """Claim a delta channel for one consumer, returning its slot index.

        MUST be called before the consumer's process is forked -- the slot index
        has to be in the object that gets pickled across. Idempotent, so a
        re-registering consumer does not consume a second slot.
        """
        if name in self._subscriptions:
            return self._subscriptions[name]
        slot = self.queue_pool.reserve()
        if slot is None:
            self.logger.error('QueuePool exhausted; no delta channel for %r. '
                              'Enlarge QueuePool.pool_size.', name)
            return None
        self._subscriptions[name] = slot
        return slot

    def channel_for(self, name: str):
        """One consumer's delta channel, resolved in this process."""
        slot = self._subscriptions.get(name)
        if slot is None:
            return None
        return self.queue_pool.slot(slot)

    @property
    def updates(self):
        """The renderer's channel (back-compat alias for channel_for(UI))."""
        return self.channel_for(self.UI_CONSUMER)

    #: How often the UI-side drain runs. `update()` already declines to do work
    #: with no browser attached or while paused, so an idle tick is cheap.
    tick_cadence = 0.5

    def start(self):
        """Start the UI-side tick that drains the delta channel.

        Without this the drain would run only once, at map initialisation:
        `SimulationInterface.run` ticks the cohort on the simulated path, but on
        the LIVE path `interfaces = [self.cohort]` and nothing else called
        `update()` — so published deltas would sit in the queue forever.
        """
        if self._tick_thread is not None:
            return
        self._halt = False
        self._tick_thread = threading.Thread(target=self._tick, daemon=True)
        self._tick_thread.start()

    def stop(self):
        self._halt = True
        thread, self._tick_thread = self._tick_thread, None
        if thread is not None:
            thread.join(timeout=2 * self.tick_cadence)

    def _tick(self):
        while not self._halt:
            try:
                self.update()
            except Exception as err:
                # A render error must not kill the acquisition loop, or the UI
                # goes permanently stale with nothing in the log to say why.
                self.logger.error('Cohort tick failed: %s', err)
            time.sleep(self.tick_cadence)

    # --- publisher side: runs in the CohortTracker worker -------------------

    def publish(self, delta: dict):
        """Hand one state delta to whoever is rendering.

        Called from the DAQ worker. Failure to publish is logged and dropped
        rather than raised: losing a stat must not take the tracker down, and the
        count makes the loss visible instead of silent.
        """
        if not self._subscriptions:
            return
        for name in self._subscriptions:
            channel = self.channel_for(name)
            if channel is None:
                continue
            try:
                channel.put(delta, block=False)
            except Exception as err:  # Full, or a manager that has gone away
                # Per-consumer: one blocked subscriber must not cost the others
                # their copy of the delta.
                self._dropped_updates += 1
                if self._dropped_updates % 100 == 1:
                    self.logger.warning('Cohort delta channel for %r unavailable '
                                        '(%d dropped): %s', name, self._dropped_updates, err)

    # --- applier side: runs in the UI process -------------------------------

    def acquire_data(self, consumer: str = None):
        """Apply the deltas published for ``consumer`` since its last drain.

        This is the seam that carries worker-side state into the processes that
        need it: the renderer by default, and each video/data receiver under its
        own name. It deliberately does NOT touch the per-peer video/data streams
        -- those belong to VideoFeed/DataFeed, and a receiver only needs the
        roster so it can find the stream to write INTO.
        """
        channel = self.channel_for(self.UI_CONSUMER if consumer is None else consumer)
        if channel is None:
            return
        for _ in range(self.max_updates_per_tick):
            try:
                delta = channel.get(block=False)
            except Empty:
                return
            except Exception as err:
                self.logger.warning('Cohort delta channel read failed: %s', err)
                return
            try:
                self._apply(delta)
            except Exception as err:
                # One malformed delta must not stop the rest of the drain.
                self.logger.error('Cohort could not apply delta %r: %s', delta.get('kind') if isinstance(delta, dict) else delta, err)
        self.logger.debug('Cohort delta drain hit the per-tick ceiling (%d)', self.max_updates_per_tick)

    def _apply(self, delta: dict):
        kind = delta.get('kind')
        if kind == 'roster':
            self._apply_roster(delta['peers'])
            return
        peer = self.peers.get(delta.get('uuid'))
        if peer is None:
            # A delta for a peer this process has not been told about yet; the
            # roster delta that introduces it may still be behind us in the
            # queue. Dropping is correct — the next stat will land.
            return
        if kind == 'meta':
            peer.metadata = delta['metadata']
        elif kind == 'stats':
            total = delta.get('total')
            if total is not None:
                peer.total_network_history.append(total)
            for other, stats in delta.get('per_other', {}).items():
                peer.network_history.setdefault(
                    other, deque(maxlen=PeerDataAcq.max_history)).append(stats)
        elif kind == 'reputation':
            peer.reputation_history.append(delta['score'])
        elif kind == 'reputation_of':
            peer.record_reputation_of(delta['subject'], delta['score'])

    def _apply_roster(self, roster: dict):
        """Mirror the owner's roster, including its queue-slot assignment.

        The slots are resolved rather than reserved: the DAQ worker already owns
        them, and claiming them again here would consume a second pair from this
        process's private view of the pool.
        """
        for uuid, entry in roster.items():
            if uuid in self.peers:
                continue
            self.peers[uuid] = PeerDataAcq(
                uuid, entry['index'], entry['identity'], NullPeerData(), self,
                self.queue_pool.slot(entry['video_slot']),
                self.queue_pool.slot(entry['data_slot']))
        for uuid in [u for u in self.peers if u not in roster]:
            del self.peers[uuid]

    # --- owner side: assignment lives here, once --------------------------

    def _next_free_index(self) -> int:
        """The lowest index no current peer holds.

        It used to be the peer's position in `enumerate(group_ids)`, which is NOT
        unique across roster churn: existing peers keep the index they were given,
        so a departure frees a position that the next arrival re-derives. Measured:
        peers A(0), B(1); A leaves, C joins → C also got 1. That index is published
        in the roster delta and had been used to build a DOM id, where a duplicate
        breaks the page rather than just confusing it. Lowest-free rather than a
        monotonic counter, so the numbering stays compact and every surviving peer
        keeps the index it already had.
        """
        used = {peer.index for peer in self.peers.values()}
        idx = 0
        while idx in used:
            idx += 1
        return idx

    def update_group(self, group_ids: dict[str, Identity]):
        """Own the roster and the queue assignment, then publish both.

        Known limitation (documented as deferred for security reasons):
        each new peer consumes two pre-allocated slots from `self.queue_pool`
        rather than creating fresh queues. Spawning multiprocessing.Queue objects
        after the daemon parent has forked workers triggers Python's "Pickling an
        AuthenticationString object is disallowed for security reasons" — an
        intentional CPython mitigation against cross-process credential leakage.
        The pool is sized to MAX_PEERS at startup; if a deployment exceeds it the
        right fix is enlarging the pool, not dynamic creation.
        """
        changed = False
        for uuid in group_ids:
            if uuid in self.peers:
                continue
            idx = self._next_free_index()
            video_slot = self.queue_pool.reserve()
            data_slot = self.queue_pool.reserve()
            if video_slot is None or data_slot is None:
                self.logger.error('QueuePool exhausted at %d peers; enlarge '
                                  'QueuePool.pool_size rather than creating '
                                  'queues after the fork', len(self.peers))
                break
            self._peer_slots[uuid] = (idx, group_ids[uuid], video_slot, data_slot)
            self.peers[uuid] = PeerDataAcq(uuid, idx, group_ids[uuid], NullPeerData(), self,
                                           self.queue_pool.slot(video_slot),
                                           self.queue_pool.slot(data_slot))
            changed = True
        to_remove = [uuid for uuid in self.peers if uuid not in group_ids]
        for uuid in to_remove:
            del self.peers[uuid]
            self._peer_slots.pop(uuid, None)
            changed = True
        if changed:
            self.publish({'kind': 'roster',
                          'peers': {uuid: {'index': slots[0], 'identity': slots[1],
                                           'video_slot': slots[2], 'data_slot': slots[3]}
                                    for uuid, slots in self._peer_slots.items()}})

    @staticmethod
    def _as_utc(when: datetime) -> datetime:
        """A naive datetime is treated as UTC rather than rejected, so one
        legacy producer cannot break the cohort clock for everyone."""
        if when.tzinfo is None:
            return when.replace(tzinfo=timezone.utc)
        return when.astimezone(timezone.utc)

    @property
    def center(self) -> Position:
        """Mean position of the peers that have REPORTED one.

        A peer is rostered before its metadata arrives, holding `NullPeerData`'s
        bare `Position` — whose `convert` raises `NotImplementedError`, so
        including it took down `DynamicMap.update_paths` (and, being a bare
        updater loop, everything registered after it) on every tick until the
        last peer had reported. An unreported peer is absent from the average,
        not at (0, 0): the placeholder would drag the map toward Null Island.
        """
        positions = []
        for uuid in self.peers:
            try:
                positions.append(self.peers[uuid].position.convert(GeoPosition))
            except (NotImplementedError, AttributeError, TypeError, ValueError):
                continue
        return GeoPosition.middle(positions)

    @property
    def time(self) -> datetime:
        """Mean peer time, over the peers that have reported one.

        The placeholder `NullPeerData.time` IS the epoch, and averaging it in
        would drag the cohort clock back by decades divided by the peer count —
        a wrong clock that still looks like a clock. Skipped instead.
        """
        times = []
        for uuid in self.peers:
            when = self._as_utc(self.peers[uuid].time)
            if when <= self.epoch:
                continue  # placeholder, not a measurement
            times.append(when - self.epoch)
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
                # This process's dict is its own copy (see Cohort's docstring),
                # so recording it locally is not enough -- the renderer lives in
                # another process and only sees what is published.
                self.cohort.publish({'kind': 'meta', 'uuid': uuid,
                                     'metadata': metadata})
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
                self.cohort.publish({'kind': 'stats', 'uuid': uuid,
                                     'total': total, 'per_other': dict(data)})
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
            self.cohort.publish({'kind': 'reputation', 'uuid': subject,
                                 'score': rep.score})
        # Transitive view: a rep_resp routed back from a peer
        # (observer != subject) is THAT observer's opinion of the subject —
        # record it as the observer's per-other reputation of the subject.
        observer = getattr(getattr(message, 'from_whom', None), 'uuid', None)
        if observer is not None and observer != subject and observer in self.cohort.peers:
            self.cohort.peers[observer].record_reputation_of(subject, rep.score)
            self.cohort.publish({'kind': 'reputation_of', 'uuid': observer,
                                 'subject': subject, 'score': rep.score})
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
                        self.logger.error('Unhandled message %s', message.function)
                    else:
                        self.logger.error('Unhandled message of type %s', message.__class__.__name__)  # noqa

            self.sleep_until(self.cadence)
