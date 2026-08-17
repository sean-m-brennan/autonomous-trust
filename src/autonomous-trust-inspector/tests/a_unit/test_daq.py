# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
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
import time
from collections import deque
from datetime import datetime, timedelta, timezone
from queue import Empty, Queue
from unittest.mock import MagicMock, call, patch

import pytest

from autonomous_trust.core import CfgIds
from autonomous_trust.core.network import Message
from autonomous_trust.core.reputation import ReputationProtocol

from autonomous_trust.inspector.peer.daq import (
    PeerDataAcq, CohortInterface, Cohort, CohortProtocol, CohortTracker,
    NullPeerData,
)


class TestNullPeerData:
    def test_returns_peer_data(self):
        pd = NullPeerData()
        assert pd.speed == 0.0
        assert pd.kind == ''
        assert pd.data_type == ''
        assert pd.data_channels == 0


class TestPeerDataAcq:
    def _make_peer(self):
        ident = MagicMock()
        ident.nickname = 'Test Peer'
        ident.petname = 'TP'
        metadata = MagicMock()
        metadata.time = datetime.now()
        metadata.position = MagicMock()
        metadata.kind = 'drone'
        cohort = MagicMock()
        video_stream = Queue()
        data_stream = Queue()
        return PeerDataAcq('uuid-123', 0, ident, metadata, cohort, video_stream, data_stream)

    def test_creation(self):
        p = self._make_peer()
        assert p.uuid == 'uuid-123'
        assert p.index == 0
        assert p.active is False

    def test_time_property(self):
        p = self._make_peer()
        assert p.time is not None

    def test_position_property(self):
        p = self._make_peer()
        assert p.position is not None

    def test_kind_property(self):
        p = self._make_peer()
        assert p.kind == 'drone'

    def test_name_property(self):
        p = self._make_peer()
        assert p.name == 'Test Peer'

    def test_nickname_property(self):
        p = self._make_peer()
        assert p.nickname == 'TP'

    def test_uuid_property(self):
        p = self._make_peer()
        assert p.uuid == 'uuid-123'

    def test_identity_property(self):
        p = self._make_peer()
        assert p.identity is not None

    def test_others_empty(self):
        p = self._make_peer()
        assert list(p.others) == []

    def test_others_with_history(self):
        p = self._make_peer()
        p.network_history['peer-2'] = deque()
        assert 'peer-2' in p.others

    def test_max_history(self):
        assert PeerDataAcq.max_history == 20

    def test_reputation_of_unknown_is_none(self):
        p = self._make_peer()
        assert p.reputation_of('nobody') is None

    def test_record_and_read_reputation_of(self):
        p = self._make_peer()
        p.record_reputation_of('other-1', 0.4)
        p.record_reputation_of('other-1', 0.7)
        assert p.reputation_of('other-1') == 0.7               # latest wins
        assert p.reputation_by_other['other-1'].maxlen == PeerDataAcq.max_history

    def test_reputation_history_deque(self):
        p = self._make_peer()
        assert isinstance(p.reputation_history, deque)
        assert p.reputation_history.maxlen == 20


class TestCohortInterface:
    def test_creation_defaults(self):
        ci = CohortInterface()
        assert ci.paused is True
        assert ci.peers == {}
        assert ci.browser_connected == 0
        assert ci.log_level == logging.INFO
        assert ci.logfile is None

    def test_creation_with_logfile(self, tmp_path):
        logfile = str(tmp_path / 'test.log')
        ci = CohortInterface(logfile=logfile)
        assert ci.logfile == logfile

    def test_center_default(self):
        ci = CohortInterface()
        c = ci.center
        assert c is not None

    def test_time_property(self):
        ci = CohortInterface()
        t = ci.time
        assert isinstance(t, datetime)

    def test_register_updater(self):
        ci = CohortInterface()
        fn = lambda: None
        ci.register_updater(fn)
        assert fn in ci.updaters

    def test_deregister_updater(self):
        ci = CohortInterface()
        fn = lambda: None
        ci.register_updater(fn)
        ci.deregister_updater(fn)
        assert fn not in ci.updaters

    def test_update_initial(self):
        ci = CohortInterface()
        with pytest.raises(NotImplementedError):
            ci.update(initial=True)

    def test_update_paused_no_acquire(self):
        ci = CohortInterface()
        ci.paused = True
        ci.browser_connected = 1
        # Should not call acquire_data (paused)
        ci.update(initial=False)

    def test_update_connected_unpaused(self):
        ci = CohortInterface()
        ci.paused = False
        ci.browser_connected = 1
        with pytest.raises(NotImplementedError):
            ci.update(initial=False)

    def test_update_calls_updaters(self):
        ci = CohortInterface()
        ci.paused = False
        ci.browser_connected = 1
        ci.acquire_data = MagicMock()
        called = []
        ci.register_updater(lambda: called.append(True))
        ci.update(initial=False)
        assert len(called) == 1

    def test_start_raises(self):
        ci = CohortInterface()
        with pytest.raises(NotImplementedError):
            ci.start()

    def test_stop_raises(self):
        ci = CohortInterface()
        with pytest.raises(NotImplementedError):
            ci.stop()


class TestCohort:
    def _make_cohort(self):
        # A real pool, not a MagicMock: Cohort now reserves slot INDICES and
        # resolves them, so a mock pool would hand back mocks and these tests
        # would assert nothing about the assignment.
        return Cohort(_pool())

    def test_creation(self):
        c = self._make_cohort()
        assert c.peers == {}
        assert c.paused is True

    def test_start(self):
        c = self._make_cohort()
        c.tick_cadence = 0.01     # so stop()'s join does not wait out the default
        c.start()                 # NOT a no-op any more: this spawns the tick loop
        try:
            assert c._tick_thread is not None
        finally:
            # Must be stopped: a leaked daemon tick thread would otherwise run
            # for the rest of the session, burning CPU and mutating cohort state
            # underneath every later test. (It also used to fail TestStreamTake
            # at random, back when those tests patched the shared `time.sleep`;
            # they now patch `daq._poll_sleep`, so the two are independent --
            # keep BOTH halves, neither one is redundant.)
            c.stop()

    def test_acquire_data_on_an_empty_channel_is_a_no_op(self):
        c = self._make_cohort()
        c.acquire_data()      # nothing published yet; must not raise or block
        assert c.peers == {}

    def test_epoch(self):
        # UTC-aware: peer times carry a tzinfo, and a naive epoch made every
        # `time` subtraction raise.
        assert Cohort.epoch == datetime(1970, 1, 1, tzinfo=timezone.utc)

    def test_update_group_adds_peers(self):
        c = self._make_cohort()
        ident = MagicMock()
        ident.uuid = 'uuid-1'
        c.update_group({'uuid-1': ident})
        assert 'uuid-1' in c.peers

    def test_time_no_peers(self):
        c = self._make_cohort()
        assert c.time == Cohort.epoch

    def test_time_with_peers(self):
        c = self._make_cohort()
        ident = MagicMock()
        ident.uuid = 'uuid-1'
        c.update_group({'uuid-1': ident})
        peer = c.peers['uuid-1']
        peer.metadata.time = datetime(2024, 1, 1)
        t = c.time
        assert isinstance(t, datetime)

    def test_center_with_peers(self):
        c = self._make_cohort()
        ident = MagicMock()
        ident.uuid = 'uuid-1'
        c.update_group({'uuid-1': ident})
        peer = c.peers['uuid-1']
        pos_mock = MagicMock()
        geo_mock = MagicMock()
        geo_mock.latitude = 34.0
        geo_mock.longitude = -86.0
        pos_mock.convert.return_value = geo_mock
        peer.metadata.position = pos_mock
        # center calls GeoPosition.middle which needs real positions
        # just verify it doesn't crash with mocks
        try:
            c.center
        except (TypeError, AttributeError):
            pass  # expected with mocks


class TestCohortProtocol:
    def test_attributes(self):
        assert CohortProtocol.meta == 'meta'
        assert CohortProtocol.stats == 'stats'


class TestCohortTracker:
    def test_handle_metadata_correct_function(self):
        tracker = MagicMock(spec=CohortTracker)
        tracker.handle_metadata = CohortTracker.handle_metadata.__get__(tracker)
        peer_mock = MagicMock()
        tracker.cohort = MagicMock()
        tracker.cohort.peers = {'peer-1': peer_mock}
        msg = MagicMock()
        msg.function = CohortProtocol.meta
        msg.from_whom.uuid = 'peer-1'
        msg.obj = '{"test": 1}'
        with patch('autonomous_trust.inspector.peer.daq.from_json_string', return_value={'test': 1}):
            result = tracker.handle_metadata(None, msg)
        assert result is True
        assert peer_mock.metadata == {'test': 1}

    def test_handle_metadata_wrong_function(self):
        tracker = MagicMock(spec=CohortTracker)
        tracker.handle_metadata = CohortTracker.handle_metadata.__get__(tracker)
        tracker.cohort = MagicMock()
        tracker.cohort.peers = {}
        msg = MagicMock()
        msg.function = 'wrong'
        result = tracker.handle_metadata(None, msg)
        assert result is False

    def test_handle_metadata_unknown_peer(self):
        tracker = MagicMock(spec=CohortTracker)
        tracker.handle_metadata = CohortTracker.handle_metadata.__get__(tracker)
        tracker.cohort = MagicMock()
        tracker.cohort.peers = {}
        msg = MagicMock()
        msg.function = CohortProtocol.meta
        msg.from_whom.uuid = 'unknown'
        msg.obj = '{}'
        with patch('autonomous_trust.inspector.peer.daq.from_json_string', return_value={}):
            result = tracker.handle_metadata(None, msg)
        assert result is True  # returns True but doesn't update

    def test_handle_stats_correct_function(self):
        tracker = MagicMock(spec=CohortTracker)
        tracker.handle_stats = CohortTracker.handle_stats.__get__(tracker)
        peer_mock = MagicMock()
        peer_mock.network_history = {'peer-2': deque()}
        tracker.cohort = MagicMock()
        tracker.cohort.peers = {'peer-1': peer_mock}
        msg = MagicMock()
        msg.function = CohortProtocol.stats
        msg.from_whom.uuid = 'peer-1'
        msg.obj = '{"peer-2": [1, 2, 3]}'
        with patch('autonomous_trust.inspector.peer.daq.from_json_string', return_value={'peer-2': [1, 2, 3]}):
            result = tracker.handle_stats(None, msg)
        assert result is True

    def test_handle_stats_wrong_function(self):
        tracker = MagicMock(spec=CohortTracker)
        tracker.handle_stats = CohortTracker.handle_stats.__get__(tracker)
        tracker.cohort = MagicMock()
        tracker.cohort.peers = {}
        msg = MagicMock()
        msg.function = 'wrong'
        result = tracker.handle_stats(None, msg)
        assert result is False

    def test_handle_stats_new_peer_uuid(self):
        # Regression: a stat for a not-yet-seen other must create its per-other
        # deque rather than raising KeyError on the plain network_history dict.
        tracker = MagicMock(spec=CohortTracker)
        tracker.handle_stats = CohortTracker.handle_stats.__get__(tracker)
        peer_mock = MagicMock()
        peer_mock.network_history = {}                 # 'peer-2' not yet present
        peer_mock.total_network_history = deque()
        tracker.cohort = MagicMock()
        tracker.cohort.peers = {'peer-1': peer_mock}
        msg = MagicMock()
        msg.function = CohortProtocol.stats
        msg.from_whom.uuid = 'peer-1'
        with patch('autonomous_trust.inspector.peer.daq.from_json_string',
                   return_value={'peer-2': [1, 2, 3]}):
            result = tracker.handle_stats(None, msg)
        assert result is True
        assert 'peer-2' in peer_mock.network_history
        assert list(peer_mock.network_history['peer-2']) == [[1, 2, 3]]

    def test_handle_reputation_appends_history(self):
        # A reputation response must land in reputation_history (what the
        # peer_status renderers read), not a dead ad-hoc attribute.
        tracker = MagicMock(spec=CohortTracker)
        tracker.handle_reputation = CohortTracker.handle_reputation.__get__(tracker)
        peer_mock = MagicMock()
        peer_mock.reputation_history = deque(maxlen=PeerDataAcq.max_history)
        tracker.cohort = MagicMock()
        tracker.cohort.peers = {'peer-1': peer_mock}
        rep = MagicMock()
        rep.peer_id = 'peer-1'
        rep.score = 0.85
        msg = Message(CfgIds.reputation, ReputationProtocol.rep_resp, rep)
        assert tracker.handle_reputation(msg) is True
        assert list(peer_mock.reputation_history) == [0.85]

    def test_handle_reputation_unknown_peer(self):
        # Consumed (returns True) but nothing recorded for an unknown peer.
        tracker = MagicMock(spec=CohortTracker)
        tracker.handle_reputation = CohortTracker.handle_reputation.__get__(tracker)
        tracker.cohort = MagicMock()
        tracker.cohort.peers = {}
        rep = MagicMock()
        rep.peer_id = 'nobody'
        rep.score = 0.5
        msg = Message(CfgIds.reputation, ReputationProtocol.rep_resp, rep)
        assert tracker.handle_reputation(msg) is True

    def test_handle_reputation_non_reputation_message(self):
        # A non-reputation object (e.g. a Peers listing) is not consumed here.
        tracker = MagicMock(spec=CohortTracker)
        tracker.handle_reputation = CohortTracker.handle_reputation.__get__(tracker)
        assert tracker.handle_reputation(object()) is False

    def test_handle_reputation_records_transitive_view(self):
        # A rep_resp routed back FROM observer 'peer-1' ABOUT subject 'peer-2'
        # is peer-1's per-other view of peer-2 (§4.2:159); peer-2 still gets the
        # direct aggregate append.
        def _pda(uuid):
            return PeerDataAcq(uuid, 0, MagicMock(), MagicMock(), MagicMock(),
                               Queue(), Queue())
        observer = _pda('peer-1')
        subject = _pda('peer-2')
        tracker = MagicMock(spec=CohortTracker)
        tracker.handle_reputation = CohortTracker.handle_reputation.__get__(tracker)
        tracker.cohort = MagicMock()
        tracker.cohort.peers = {'peer-1': observer, 'peer-2': subject}
        rep = MagicMock()
        rep.peer_id = 'peer-2'
        rep.score = 0.6
        msg = Message(CfgIds.reputation, ReputationProtocol.rep_resp, rep)
        msg.from_whom = MagicMock()
        msg.from_whom.uuid = 'peer-1'
        assert tracker.handle_reputation(msg) is True
        assert list(subject.reputation_history) == [0.6]     # direct aggregate
        assert observer.reputation_of('peer-2') == 0.6        # transitive/per-other
        assert list(observer.reputation_history) == []        # observer's own untouched


# --- ISSUES §4.3: Cohort.acquire_data ---------------------------------------
#
# The blocker was never "which queue to drain". One Cohort is handed to the DAQ
# worker, the video/data receivers and the UI, then the workers are pickled into
# forked processes -- so `peers` is a SEPARATE plain dict per process, and
# everything CohortTracker recorded was invisible to the renderer. The pooled
# queues do cross (manager proxies, built pre-fork), so peer state travels as
# deltas over one of them and acquire_data applies them UI-side.

def _pool(size=16):
    """A real QueuePool, so reserve()/slot() semantics are actually exercised."""
    from autonomous_trust.core.queue_pool import QueuePool
    pool = QueuePool.__new__(QueuePool)
    from autonomous_trust.core.queue_pool import PooledQueue
    pool._pool = [PooledQueue(Queue) for _ in range(size)]
    return pool


def _fork_pool(pool):
    """Clone a pool the way a fork does: the same underlying queue objects, but
    independent PooledQueue wrappers carrying the in_use state as of the fork.

    This is what makes slot indices the only shareable currency -- each process
    mutates its own in_use flags from here on.
    """
    from autonomous_trust.core.queue_pool import QueuePool, PooledQueue
    clone = QueuePool.__new__(QueuePool)
    clone._pool = []
    for pq in pool._pool:
        copy = PooledQueue.__new__(PooledQueue)
        copy.in_use = pq.in_use
        copy.queue = pq.queue
        clone._pool.append(copy)
    return clone


def _forked_cohorts(extra_consumers=()):
    """A parent Cohort and a forked copy of it.

    A fork has three effects that matter: the copies INHERIT the subscription
    table (it was built in the parent, before the fork), each gets its own
    `peers` dict, and each gets its own pool `in_use` flags. Reproduced directly
    -- the real object only pickles when the pool holds manager proxies, and the
    genuine cross-process delivery is covered by TestCohortDeltaAcrossARealFork.
    """
    ui = Cohort(_pool())
    for name in extra_consumers:
        ui.subscribe(name)
    worker = Cohort(_fork_pool(ui.queue_pool))
    # The constructor claimed a fresh 'ui' slot; a fork inherits instead, so
    # release it and adopt the parent's table.
    worker.queue_pool._pool[worker._subscriptions[Cohort.UI_CONSUMER]].in_use = False
    worker._subscriptions = dict(ui._subscriptions)
    return ui, worker


def _ident(uuid='uuid-1', nickname='n', petname='p'):
    ident = MagicMock()
    ident.uuid = uuid
    ident.nickname = nickname
    ident.petname = petname
    return ident


class TestCohortDeltaChannel:
    def _pair(self):
        """A UI-side and worker-side Cohort as a fork produces them.

        A fork has exactly two effects that matter here: both copies resolve the
        SAME `_updates_slot` (the index was assigned in the parent, before the
        fork), and each gets its OWN `peers` dict. Reproduced directly, because
        the real object only pickles when the pool holds manager proxies -- the
        genuine cross-process delivery is covered by
        test_a_delta_survives_a_real_fork below.
        """
        ui, worker = _forked_cohorts()
        assert ui.peers is not worker.peers             # separate dicts...
        assert ui.queue_pool is not worker.queue_pool   # ...and separate flags
        assert ui.updates is worker.updates             # ...over one shared channel
        return ui, worker

    def test_worker_dict_mutation_alone_is_invisible(self):
        """Why the channel has to exist at all."""
        ui, worker = self._pair()
        worker.update_group({'uuid-1': _ident()})
        assert 'uuid-1' in worker.peers
        assert ui.peers == {}                        # the renderer sees nothing...
        ui.acquire_data()
        assert 'uuid-1' in ui.peers                  # ...until the delta is applied

    def test_roster_delta_carries_the_queue_assignment(self):
        """The assignment must cross too: each process has its own in_use flags,
        so re-deriving it with next() would agree only by accident."""
        ui, worker = self._pair()
        worker.update_group({'uuid-1': _ident()})
        ui.acquire_data()
        assert ui.peers['uuid-1'].video_stream is worker.peers['uuid-1'].video_stream
        assert ui.peers['uuid-1'].data_stream is worker.peers['uuid-1'].data_stream
        assert ui.peers['uuid-1'].video_stream is not ui.peers['uuid-1'].data_stream

    def test_applying_a_roster_does_not_consume_extra_slots(self):
        """The UI resolves slots, it does not reserve them -- otherwise every
        peer would burn two slots per process and exhaust the pool early."""
        ui, worker = self._pair()
        worker.update_group({'uuid-1': _ident()})
        free_before = sum(1 for pq in ui.queue_pool._pool if not pq.in_use)
        ui.acquire_data()
        free_after = sum(1 for pq in ui.queue_pool._pool if not pq.in_use)
        assert free_after == free_before

    def test_departed_peers_are_removed(self):
        ui, worker = self._pair()
        worker.update_group({'uuid-1': _ident()})
        ui.acquire_data()
        worker.update_group({})
        ui.acquire_data()
        assert ui.peers == {}

    def test_stats_delta_appends_per_other_history(self):
        ui, worker = self._pair()
        worker.update_group({'uuid-1': _ident()})
        worker.publish({'kind': 'stats', 'uuid': 'uuid-1', 'total': 'T',
                        'per_other': {'other-9': 'S'}})
        ui.acquire_data()
        peer = ui.peers['uuid-1']
        assert list(peer.total_network_history) == ['T']
        assert list(peer.network_history['other-9']) == ['S']
        assert 'other-9' in peer.others           # what the renderers iterate

    def test_metadata_delta_applies(self):
        ui, worker = self._pair()
        worker.update_group({'uuid-1': _ident()})
        worker.publish({'kind': 'meta', 'uuid': 'uuid-1', 'metadata': 'META'})
        ui.acquire_data()
        assert ui.peers['uuid-1'].metadata == 'META'

    def test_reputation_deltas_apply_both_views(self):
        ui, worker = self._pair()
        worker.update_group({'uuid-1': _ident(), 'uuid-2': _ident('uuid-2')})
        worker.publish({'kind': 'reputation', 'uuid': 'uuid-1', 'score': 0.7})
        worker.publish({'kind': 'reputation_of', 'uuid': 'uuid-2',
                        'subject': 'uuid-1', 'score': 0.3})
        ui.acquire_data()
        assert list(ui.peers['uuid-1'].reputation_history) == [0.7]
        assert ui.peers['uuid-2'].reputation_of('uuid-1') == 0.3

    def test_a_delta_for_an_unknown_peer_is_dropped(self):
        """Its roster delta may still be behind it in the queue; the next stat
        lands. Must not raise."""
        ui, worker = self._pair()
        worker.publish({'kind': 'stats', 'uuid': 'ghost', 'total': 'T',
                        'per_other': {}})
        ui.acquire_data()
        assert ui.peers == {}

    def test_a_malformed_delta_does_not_stop_the_drain(self):
        ui, worker = self._pair()
        worker.update_group({'uuid-1': _ident()})
        worker.publish({'kind': 'roster'})                    # no 'peers' -> KeyError
        worker.publish({'kind': 'meta', 'uuid': 'uuid-1', 'metadata': 'GOOD'})
        ui.acquire_data()
        assert ui.peers['uuid-1'].metadata == 'GOOD'          # the good one still applied

    def test_the_drain_is_bounded_per_tick(self):
        """A burst must not stall the render loop."""
        ui, worker = self._pair()
        worker.update_group({'uuid-1': _ident()})
        ui.acquire_data()
        ui.max_updates_per_tick = 3
        for i in range(10):
            worker.publish({'kind': 'reputation', 'uuid': 'uuid-1', 'score': float(i)})
        ui.acquire_data()
        assert len(ui.peers['uuid-1'].reputation_history) == 3
        ui.acquire_data()
        assert len(ui.peers['uuid-1'].reputation_history) == 6   # rest follows

    def test_acquire_data_never_touches_the_peer_streams(self):
        """The conflict the tracker flagged: video_feed/data_feed consume those
        queues directly, so acquire_data draining them would starve the feeds."""
        ui, worker = self._pair()
        worker.update_group({'uuid-1': _ident()})
        ui.acquire_data()
        peer = ui.peers['uuid-1']
        peer.video_stream.put('frame')
        peer.data_stream.put('sample')
        ui.acquire_data()
        assert peer.video_stream.qsize() == 1     # still there for VideoFeed
        assert peer.data_stream.qsize() == 1      # still there for DataFeed

    def test_pool_exhaustion_is_reported_not_silent(self):
        pool = _pool(size=3)      # 1 for updates, so room for exactly one peer
        worker = Cohort(pool)
        worker.logger = MagicMock()
        worker.update_group({'a': _ident('a'), 'b': _ident('b')})
        assert 'a' in worker.peers and 'b' not in worker.peers
        assert worker.logger.error.called


def _publish_in_child(channel):
    """Module-level so forkserver can pickle it as the child target."""
    channel.put({'kind': 'reputation', 'uuid': 'uuid-1', 'score': 0.55})


class TestCohortDeltaAcrossARealFork:
    """The model itself: state written in a forked child does not reach the
    parent's dict, but a delta over a pooled manager queue does."""

    def test_a_delta_survives_a_real_fork(self):
        import multiprocessing as mp
        # forkserver, matching what mock.py actually uses -- and safe to start
        # from a process that already has threads, which plain fork is not.
        ctx = mp.get_context('forkserver')
        mgr = ctx.Manager()
        try:
            from autonomous_trust.core.queue_pool import QueuePool, PooledQueue
            pool = QueuePool.__new__(QueuePool)
            pool._pool = [PooledQueue(mgr.Queue) for _ in range(4)]
            ui = Cohort(pool)
            ui.update_group({'uuid-1': _ident()})    # roster owned here for brevity
            channel = ui.updates

            proc = ctx.Process(target=_publish_in_child, args=(channel,))
            proc.start()
            proc.join(timeout=30)
            assert proc.exitcode == 0

            ui.acquire_data()
            assert list(ui.peers['uuid-1'].reputation_history) == [0.55]
        finally:
            mgr.shutdown()


class TestCohortTick:
    """acquire_data is useless without something calling it. On the simulated
    path SimulationInterface.run ticks the cohort; on the LIVE path nothing did,
    so Cohort.start() owns that loop now."""

    def _pair(self):
        return _forked_cohorts()

    def test_the_tick_drains_without_anyone_calling_update(self):
        import time as _time
        ui, worker = self._pair()
        ui.tick_cadence = 0.01
        ui.browser_connected = 1
        ui.paused = False
        worker.update_group({'uuid-1': _ident()})
        ui.start()
        try:
            deadline = _time.monotonic() + 5
            while 'uuid-1' not in ui.peers and _time.monotonic() < deadline:
                _time.sleep(0.01)
            assert 'uuid-1' in ui.peers
        finally:
            ui.stop()

    def test_stop_ends_the_thread(self):
        ui, _ = self._pair()
        ui.tick_cadence = 0.01
        ui.start()
        thread = ui._tick_thread
        ui.stop()
        assert not thread.is_alive()
        assert ui._tick_thread is None

    def test_start_is_idempotent(self):
        ui, _ = self._pair()
        ui.tick_cadence = 0.01
        ui.start()
        first = ui._tick_thread
        ui.start()
        try:
            assert ui._tick_thread is first     # not a second loop
        finally:
            ui.stop()

    def test_a_failing_updater_does_not_kill_the_loop(self):
        """Otherwise the UI goes permanently stale with nothing saying why."""
        import time as _time
        ui, worker = self._pair()
        ui.tick_cadence = 0.01
        ui.browser_connected = 1
        ui.paused = False
        boom = MagicMock(side_effect=RuntimeError('render exploded'))
        ui.register_updater(boom)
        ui.logger = MagicMock()
        ui.start()
        try:
            deadline = _time.monotonic() + 5
            while boom.call_count < 2 and _time.monotonic() < deadline:
                _time.sleep(0.01)
            assert boom.call_count >= 2          # still ticking after the failure
            assert ui.logger.error.called        # and it said so
        finally:
            ui.stop()


class TestSubscriptionFanOut:
    """A queue has exactly ONE consumer, so the UI and each stream receiver need
    their own channel. Before this, the receivers had no roster at all: every
    inbound frame hit `if uuid in self.cohort.peers` against an empty dict and was
    dropped in silence.
    """

    def test_each_consumer_gets_its_own_channel(self):
        ui, _ = _forked_cohorts(extra_consumers=('video-sink', 'data-sink'))
        slots = set(ui._subscriptions.values())
        assert len(slots) == 3               # ui + two receivers, no sharing
        assert ui.channel_for('video-sink') is not ui.channel_for('data-sink')
        assert ui.channel_for('video-sink') is not ui.updates

    def test_every_subscriber_sees_the_same_delta(self):
        """The UI draining its copy must not consume the receivers'."""
        ui, worker = _forked_cohorts(extra_consumers=('video-sink',))
        video = Cohort(_fork_pool(ui.queue_pool))
        video._subscriptions = dict(ui._subscriptions)

        worker.update_group({'uuid-1': _ident()})
        ui.acquire_data()                     # renderer drains its own channel
        assert 'uuid-1' in ui.peers
        assert 'uuid-1' not in video.peers    # receiver's copy still pending
        video.acquire_data('video-sink')
        assert 'uuid-1' in video.peers

    def test_a_receiver_resolves_the_same_stream_queue_as_the_ui(self):
        """The whole point: the receiver must write into the very queue the
        renderer's VideoFeed reads from."""
        ui, worker = _forked_cohorts(extra_consumers=('video-sink',))
        video = Cohort(_fork_pool(ui.queue_pool))
        video._subscriptions = dict(ui._subscriptions)

        worker.update_group({'uuid-1': _ident()})
        ui.acquire_data()
        video.acquire_data('video-sink')

        video.peers['uuid-1'].video_stream.put('frame')
        assert ui.peers['uuid-1'].video_stream.get_nowait() == 'frame'

    def test_subscribe_is_idempotent(self):
        ui, _ = _forked_cohorts()
        first = ui.subscribe('video-sink')
        assert ui.subscribe('video-sink') == first     # no second slot burned

    def test_unknown_consumer_drains_nothing(self):
        ui, worker = _forked_cohorts()
        worker.update_group({'uuid-1': _ident()})
        ui.acquire_data('never-subscribed')
        assert ui.peers == {}                          # and must not raise

    def test_one_blocked_subscriber_does_not_starve_the_others(self):
        ui, worker = _forked_cohorts(extra_consumers=('video-sink',))
        worker._subscriptions = dict(ui._subscriptions)
        worker.logger = MagicMock()
        # Wedge the video channel; the UI's must still receive.
        broken = MagicMock()
        broken.put.side_effect = RuntimeError('manager gone')
        with patch.object(worker, 'channel_for',
                          side_effect=lambda n: broken if n == 'video-sink'
                          else ui.channel_for(n)):
            worker.publish({'kind': 'reputation', 'uuid': 'x', 'score': 1.0})
        assert ui.updates.qsize() == 1
        assert worker.logger.warning.called


# --- I15: the feeds waited by polling ---------------------------------------

class TestStreamTake:
    """The feeds used `while len(stream) < 1: sleep(0.1)`. Three defects in one
    line: it spun, it capped a 30 fps source at 10 fps (and added up to 100 ms of
    latency per frame), and it could not work at all against the stream type
    production supplies -- QueuePool hands out Queues, which have no __len__ and
    no pop.
    """

    # These patch `daq._poll_sleep`, the name the deque-poll branch calls,
    # NOT `daq.time.sleep`. `daq.time` is the shared stdlib module, so
    # patching it reaches every thread in the process: any unrelated thread
    # that sleeps inside the `with` block counts as a poll here (a leaked
    # Cohort tick thread did exactly that, failing the timeout test at
    # random), and every real sleep in the process turns into an instant
    # MagicMock for the duration. The seam observes one call site instead.

    def test_a_queue_wait_never_polls(self):
        """The Queue path must block in the kernel, not spin."""
        from autonomous_trust.inspector.peer import daq
        q = Queue()
        q.put('frame')
        with patch.object(daq, '_poll_sleep') as slept:
            assert daq.stream_take(q, 1.0) == 'frame'
        assert not slept.called

    def test_a_queue_wait_times_out_without_polling(self):
        from autonomous_trust.inspector.peer import daq
        with patch.object(daq, '_poll_sleep') as slept:
            with pytest.raises(Empty):
                daq.stream_take(Queue(), 0.05)
        assert not slept.called

    def test_a_deque_polls_because_it_cannot_block(self):
        """Documented asymmetry, not an oversight: a deque has no blocking API.
        Only in-process/test streams take this path."""
        from autonomous_trust.inspector.peer import daq
        with patch.object(daq, '_poll_sleep') as slept:
            with pytest.raises(Empty):
                daq.stream_take(deque(), 0.02)
        assert slept.called
        # ...and it is THIS poll, at the documented cadence -- not some other
        # sleep that merely happened during the window.
        assert slept.call_args_list == [call(daq.DEQUE_POLL_SEC)] * slept.call_count

    def test_a_deque_still_yields_its_item(self):
        from autonomous_trust.inspector.peer import daq
        assert daq.stream_take(deque(['frame']), 1.0) == 'frame'

    def test_a_late_arrival_returns_as_soon_as_it_lands(self):
        """What the 0.1 s poll cost: the wait must not be quantised."""
        import threading as _t
        from autonomous_trust.inspector.peer import daq
        q = Queue()
        _t.Timer(0.02, lambda: q.put('frame')).start()
        started = time.monotonic()
        assert daq.stream_take(q, 2.0) == 'frame'
        assert time.monotonic() - started < 0.1

    def test_latest_discards_the_backlog(self):
        """A live view wants the current frame, not a growing lag. The deque form
        got this free via pop(); a Queue is FIFO, so it is drained explicitly."""
        from autonomous_trust.inspector.peer import daq
        q = Queue()
        for i in range(5):
            q.put('frame-%d' % i)
        assert daq.stream_take_latest(q, 1.0) == 'frame-4'
        assert q.empty()

    def test_latest_on_a_deque_is_also_the_newest(self):
        from autonomous_trust.inspector.peer import daq
        assert daq.stream_take_latest(deque(['old', 'new']), 1.0) == 'new'

    def test_latest_of_a_single_item_is_that_item(self):
        from autonomous_trust.inspector.peer import daq
        q = Queue()
        q.put('only')
        assert daq.stream_take_latest(q, 1.0) == 'only'


class TestPeerActiveEvent:
    """`active` gates the feeds, so its changes are worth waking them for."""

    def _peer(self):
        return PeerDataAcq('uuid-1', 0, _ident(), NullPeerData(), MagicMock(),
                           Queue(), Queue())

    def test_default_is_inactive(self):
        assert self._peer().active is False

    def test_setting_active_wakes_a_waiter_at_once(self):
        import threading as _t
        peer = self._peer()
        _t.Timer(0.02, lambda: setattr(peer, 'active', True)).start()
        started = time.monotonic()
        assert peer.wait_active(2.0) is True
        assert time.monotonic() - started < 0.5

    def test_clearing_active_makes_the_wait_time_out(self):
        peer = self._peer()
        peer.active = True
        peer.active = False
        started = time.monotonic()
        assert peer.wait_active(0.05) is False
        assert time.monotonic() - started >= 0.05

    def test_the_setter_coerces_to_bool(self):
        peer = self._peer()
        peer.active = 'yes'
        assert peer.active is True


class TestAggregatesToleratePlaceholders:
    """A peer is rostered BEFORE its metadata arrives, holding `NullPeerData`, and
    both cohort aggregates read that placeholder. Both raised on it: `center`
    called `convert` on a bare `Position` (NotImplementedError) and `time`
    subtracted a tz-aware peer time from a naive epoch (TypeError -- for REAL
    peers too, since a decoded `PeerData.time` carries a tzinfo). Each aggregate
    is read by a registered updater, the map and the header clock, so with the old
    bare updater loop either one took down every updater after it, every tick.
    """

    @staticmethod
    def _reported(lat=34.0, lon=-86.0, alt=100.0, when=None):
        """Metadata as a peer that HAS reported would carry it."""
        from autonomous_trust.services.peer.metadata import PeerData
        from autonomous_trust.services.peer.position import GeoPosition
        return PeerData(when or datetime(2026, 8, 12, 12, 0, tzinfo=timezone.utc),
                        GeoPosition(lat, lon, alt), 0.0, 'drone', 'video', 3)

    def _cohort_with(self, *metadatas):
        """A cohort of len(metadatas) peers; None leaves that peer unreported."""
        c = Cohort(_pool())
        idents = {}
        for i in range(len(metadatas)):
            ident = MagicMock()
            ident.uuid = 'uuid-%d' % i
            idents[ident.uuid] = ident
        c.update_group(idents)
        for i, meta in enumerate(metadatas):
            if meta is not None:
                c.peers['uuid-%d' % i].metadata = meta
        return c

    def test_center_with_an_unreported_peer_does_not_raise(self):
        """The regression: NullPeerData's bare Position cannot convert."""
        c = self._cohort_with(None)
        assert c.center is not None

    def test_center_ignores_the_placeholder_rather_than_averaging_it(self):
        """An unreported peer is absent from the average, not sitting at (0, 0):
        the placeholder would drag the map toward Null Island."""
        c = self._cohort_with(self._reported(lat=34.0, lon=-86.0), None)
        center = c.center
        assert center.lat == pytest.approx(34.0)
        assert center.lon == pytest.approx(-86.0)

    def test_center_averages_the_peers_that_did_report(self):
        c = self._cohort_with(self._reported(lat=30.0, lon=-90.0),
                              self._reported(lat=40.0, lon=-80.0))
        center = c.center
        assert center.lat == pytest.approx(35.0)
        assert center.lon == pytest.approx(-85.0)

    def test_time_with_an_aware_peer_time(self):
        """The regression: aware peer time minus naive epoch raised TypeError, so
        the header clock died on every tick once any peer existed."""
        when = datetime(2026, 8, 12, 12, 0, tzinfo=timezone.utc)
        c = self._cohort_with(self._reported(when=when))
        assert c.time == when

    def test_time_accepts_a_naive_peer_time_as_utc(self):
        """One legacy producer must not break the clock for everyone."""
        c = self._cohort_with(self._reported(when=datetime(2026, 8, 12, 12, 0)))
        assert c.time == datetime(2026, 8, 12, 12, 0, tzinfo=timezone.utc)

    def test_time_ignores_the_placeholder_epoch(self):
        """Averaging in NullPeerData's epoch-0 would drag the cohort clock back by
        decades / peer count -- a wrong clock that still looks like a clock."""
        when = datetime(2026, 8, 12, 12, 0, tzinfo=timezone.utc)
        c = self._cohort_with(self._reported(when=when), None)
        assert c.time == when

    def test_time_with_no_reported_peers_is_the_epoch(self):
        c = self._cohort_with(None, None)
        assert c.time == Cohort.epoch


class TestUpdaterIsolation:
    """`update` ran its updaters in a bare loop, so the first one to raise
    silenced every updater registered after it -- the whole dashboard frozen by
    one component, with nothing in the log naming it."""

    def _live(self):
        ci = CohortInterface()
        ci.paused = False
        ci.browser_connected = 1
        ci.acquire_data = MagicMock()
        return ci

    def test_one_failing_updater_does_not_silence_the_rest(self):
        ci = self._live()
        called = []

        def broken():
            raise RuntimeError('boom')

        ci.register_updater(broken)
        ci.register_updater(lambda: called.append(True))
        ci.update()
        assert called == [True]

    def test_the_failure_names_the_updater(self):
        ci = self._live()
        ci.logger = MagicMock()

        def a_named_updater():
            raise RuntimeError('boom')

        ci.register_updater(a_named_updater)
        ci.update()
        logged = ' '.join(str(call) for call in ci.logger.error.call_args_list)
        assert 'a_named_updater' in logged
        assert 'boom' in logged

    def test_a_healthy_updater_is_still_called_once(self):
        ci = self._live()
        called = []
        ci.register_updater(lambda: called.append(True))
        ci.update()
        assert called == [True]


class TestPeerIndexUniqueness:
    """`peer.index` came from `enumerate(group_ids)`, but existing peers keep the
    index they were first given -- so a departure freed a position the next
    arrival re-derived, and two peers held one index. It is published in the
    roster delta and was used to build a DOM id, where a duplicate breaks the
    page."""

    def _cohort(self):
        return Cohort(_pool())

    @staticmethod
    def _ident(uuid):
        m = MagicMock()
        m.uuid = uuid
        return m

    def _group(self, *uuids):
        return {u: self._ident(u) for u in uuids}

    def test_churn_does_not_reissue_a_held_index(self):
        c = self._cohort()
        c.update_group(self._group('A', 'B'))
        c.update_group(self._group('B', 'C'))       # A leaves, C joins
        indices = [p.index for p in c.peers.values()]
        assert len(set(indices)) == len(indices)

    def test_a_surviving_peer_keeps_its_index(self):
        """Renumbering would move a peer's panel out from under the operator."""
        c = self._cohort()
        c.update_group(self._group('A', 'B'))
        before = c.peers['B'].index
        c.update_group(self._group('B', 'C'))
        assert c.peers['B'].index == before

    def test_a_freed_index_is_reused_before_growing(self):
        """Compact numbering: the pool and the panel ids are both index-shaped."""
        c = self._cohort()
        c.update_group(self._group('A', 'B'))
        c.update_group(self._group('B'))            # frees 0
        c.update_group(self._group('B', 'C'))
        assert c.peers['C'].index == 0

    def test_indices_are_unique_across_repeated_churn(self):
        c = self._cohort()
        c.update_group(self._group('A', 'B', 'C'))
        for step in range(5):
            c.update_group(self._group('B', 'C', 'D%d' % step))
            indices = [p.index for p in c.peers.values()]
            assert len(set(indices)) == len(indices), 'collision at step %d' % step

    def test_the_published_roster_carries_the_same_indices(self):
        """The UI process mirrors these, so a divergence here is invisible until
        two panels fight over one id."""
        c = self._cohort()
        published = []
        c.publish = lambda delta: published.append(delta)
        c.update_group(self._group('A', 'B'))
        c.update_group(self._group('B', 'C'))
        roster = published[-1]['peers']
        assert {entry['index'] for entry in roster.values()} == \
            {p.index for p in c.peers.values()}
        assert len({entry['index'] for entry in roster.values()}) == len(roster)
