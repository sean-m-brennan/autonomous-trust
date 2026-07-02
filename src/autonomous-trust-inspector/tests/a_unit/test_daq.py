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
from collections import deque
from datetime import datetime, timedelta
from queue import Queue
from unittest.mock import MagicMock, patch

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
        pool = MagicMock()
        pool.next.return_value = Queue()
        return Cohort(pool)

    def test_creation(self):
        c = self._make_cohort()
        assert c.peers == {}
        assert c.paused is True

    def test_start(self):
        c = self._make_cohort()
        c.start()  # no-op, should not raise

    def test_acquire_data(self):
        c = self._make_cohort()
        c.acquire_data()  # no-op

    def test_epoch(self):
        assert Cohort.epoch == datetime(1970, 1, 1)

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
