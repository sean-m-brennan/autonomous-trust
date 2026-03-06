import logging
from collections import deque, namedtuple
from datetime import datetime
from queue import Queue
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

try:
    from autonomous_trust.inspector.dash_components.core import (
        DashControl, DashComponent, make_icon, IconSize, WSClient, get_ip_addr,
    )
    from autonomous_trust.inspector.dash_components.dynamic_map import DynamicMap, Coord
    from autonomous_trust.inspector.dash_components.timer import TimerTitle
    from autonomous_trust.inspector.dash_components.data_feed import DataFeed
    from autonomous_trust.inspector.dash_components.video_feed import VideoFeed
    from autonomous_trust.inspector.dash_components.peer_status import PeerStatus
    from autonomous_trust.inspector.peer.daq import PeerDataAcq, CohortInterface
    has_dash = True
except (ImportError, ModuleNotFoundError) as _e:
    has_dash = False

pytestmark = pytest.mark.skipif(not has_dash,
                                reason='dash_components dependencies not available')


def _make_ctl(**kwargs):
    with patch('autonomous_trust.inspector.dash_components.core.get_ip_addr', return_value='127.0.0.1'):
        return DashControl('test', 'Test App', host='127.0.0.1', **kwargs)


def _make_peer(uuid='uuid-1', index=0):
    ident = MagicMock()
    ident.fullname = 'Test Peer'
    ident.nickname = 'TP'
    metadata = MagicMock()
    metadata.time = datetime.now()
    metadata.position = MagicMock()
    metadata.position.convert.return_value = MagicMock(lat=34.0, lon=-86.0, alt=100.0, x=34.0, y=-86.0)
    metadata.kind = 'drone'
    metadata.data_type = 'video'
    metadata.data_channels = 3
    cohort = MagicMock(spec=CohortInterface)
    cohort.paused = True
    return PeerDataAcq(uuid, index, ident, metadata, cohort, deque(), deque())


class TestCoord:
    def test_creation(self):
        c = Coord(lat=[1, 2], lon=[3, 4])
        assert c.lat == [1, 2]
        assert c.lon == [3, 4]


class TestDynamicMap:
    def _make_map(self):
        ctl = _make_ctl()
        cohort = MagicMock(spec=CohortInterface)
        cohort.peers = {}
        cohort.center = MagicMock()
        cohort.center.convert.return_value = MagicMock(lat=34.0, lon=-86.0)
        cohort.register_updater = MagicMock()
        cohort.update = MagicMock()
        logger = logging.getLogger('test_map')
        return DynamicMap(ctl, cohort, logger)

    def test_creation(self):
        dm = self._make_map()
        assert dm.fig is not None
        assert dm.following == ''
        assert dm.pitch == DynamicMap.max_pitch

    def test_div(self):
        dm = self._make_map()
        d = dm.div()
        assert d is not None

    def test_trim_traces(self):
        dm = self._make_map()
        dm.cohort.peers = {'uuid-1': MagicMock(active=True)}
        dm.coords = {'uuid-1': Coord(deque([1, 2, 3, 4, 5]), deque([10, 20, 30, 40, 50]))}
        dm.trim_traces(2)
        assert dm.skip_trace is True
        assert len(dm.coords['uuid-1'].lat) == 2

    def test_trim_traces_inactive_peer(self):
        dm = self._make_map()
        dm.cohort.peers = {'uuid-1': MagicMock(active=False)}
        dm.coords = {'uuid-1': Coord(deque([1, 2, 3]), deque([10, 20, 30]))}
        dm.trim_traces(1)

    def test_update_paths_no_center(self):
        dm = self._make_map()
        dm.cohort.center = None
        dm.update_paths()  # should return early

    def test_update_paths_no_peers(self):
        dm = self._make_map()
        dm.cohort.center = MagicMock()
        dm.cohort.center.convert.return_value = MagicMock(lat=34.0, lon=-86.0)
        dm.cohort.peers = {}
        dm.update_paths()  # should return early

    def test_default_scale(self):
        assert DynamicMap.default_scale == 10000

    def test_trace_len(self):
        assert DynamicMap.trace_len == 10

    def test_update_paths_with_active_peer(self):
        dm = self._make_map()
        peer = MagicMock()
        peer.active = True
        peer.position = MagicMock()
        peer.position.convert.return_value = MagicMock(lat=34.0, lon=-86.0, x=34.0, y=-86.0)
        dm.cohort.peers = {'uuid-1': peer}
        dm.cohort.center = MagicMock()
        dm.cohort.center.convert.return_value = MagicMock(lat=34.0, lon=-86.0)
        dm.center = dm.cohort.center.convert.return_value
        dm.initialized = True
        dm.update_paths()
        assert 'uuid-1' in dm.peer_tracker

    def test_update_paths_with_inactive_peer(self):
        dm = self._make_map()
        peer = MagicMock()
        peer.active = False
        dm.cohort.peers = {'uuid-1': peer}
        dm.cohort.center = MagicMock()
        dm.cohort.center.convert.return_value = MagicMock(lat=34.0, lon=-86.0)
        dm.center = dm.cohort.center.convert.return_value
        dm.update_paths()
        assert dm.peer_tracker.get('uuid-1') is False

    def test_update_paths_following(self):
        dm = self._make_map()
        peer = MagicMock()
        peer.active = True
        peer.position = MagicMock()
        peer.position.convert.return_value = MagicMock(lat=35.0, lon=-87.0, x=35.0, y=-87.0)
        dm.cohort.peers = {'uuid-1': peer}
        dm.cohort.center = MagicMock()
        dm.cohort.center.convert.return_value = MagicMock(lat=34.0, lon=-86.0)
        dm.center = dm.cohort.center.convert.return_value
        dm.following = 'uuid-1'
        dm.update_paths()

    def test_update_paths_existing_traces(self):
        dm = self._make_map()
        peer = MagicMock()
        peer.active = True
        peer.position = MagicMock()
        peer.position.convert.return_value = MagicMock(lat=34.0, lon=-86.0, x=34.0, y=-86.0)
        dm.cohort.peers = {'uuid-1': peer}
        dm.cohort.center = MagicMock()
        dm.cohort.center.convert.return_value = MagicMock(lat=34.0, lon=-86.0)
        dm.center = dm.cohort.center.convert.return_value
        dm.peer_tracker = {'uuid-1': True}
        dm.coords = {'uuid-1': Coord(deque([34.0]), deque([-86.0]))}
        dm.update_paths()

    def test_update_paths_skip_trace(self):
        dm = self._make_map()
        dm.skip_trace = True
        dm.cohort.center = MagicMock()
        dm.cohort.center.convert.return_value = MagicMock(lat=34.0, lon=-86.0)
        dm.cohort.peers = {'uuid-1': MagicMock(active=True)}
        dm.center = dm.cohort.center.convert.return_value
        dm.update_paths()
        assert dm.skip_trace is False

    def test_add_traces(self):
        dm = self._make_map()
        peer = MagicMock()
        peer.position = MagicMock()
        peer.position.convert.return_value = MagicMock(lat=34.0, lon=-86.0)
        dm.cohort.peers = {'uuid-1': peer}
        dm.add_traces(0, 'uuid-1')
        assert 'uuid-1' in dm.color_map


class TestTimerTitle:
    def _make_timer(self):
        ctl = _make_ctl()
        cohort = MagicMock(spec=CohortInterface)
        cohort.time = datetime.now()
        cohort.register_updater = MagicMock()
        logger = logging.getLogger('test_timer')
        return TimerTitle(ctl, cohort, logger)

    def test_creation(self):
        t = self._make_timer()
        assert t.cohort is not None
        assert t.logger is not None

    def test_div(self):
        t = self._make_timer()
        d = t.div('Test Title')
        assert d is not None

    def test_update_time(self):
        t = self._make_timer()
        t.cohort.time = datetime(2024, 6, 15, 12, 0, 0)
        t.update_time()

    def test_update_time_none(self):
        t = self._make_timer()
        t.cohort.time = None
        t.update_time()  # should not raise


class TestDataFeed:
    def test_creation(self):
        ctl = _make_ctl()
        peer = _make_peer()
        df = DataFeed(ctl, peer, 0)
        assert df.fig is not None
        assert df.halt is False

    def test_div(self):
        ctl = _make_ctl()
        peer = _make_peer()
        df = DataFeed(ctl, peer, 0)
        d = df.div('Test Data')
        assert d is not None

    def test_div_custom_style(self):
        ctl = _make_ctl()
        peer = _make_peer()
        df = DataFeed(ctl, peer, 0)
        d = df.div('Test', style={'width': '100%'})
        assert d is not None


class TestVideoFeed:
    def test_creation(self):
        ctl = _make_ctl()
        peer = _make_peer()
        vf = VideoFeed(ctl, peer, 0)
        assert vf.halt is False
        assert vf.via_ws is False

    def test_div(self):
        ctl = _make_ctl()
        peer = _make_peer()
        vf = VideoFeed(ctl, peer, 0)
        d = vf.div('Video Feed')
        assert d is not None

    def test_div_custom_style(self):
        ctl = _make_ctl()
        peer = _make_peer()
        vf = VideoFeed(ctl, peer, 0)
        d = vf.div('Video', style={'padding': 0})
        assert d is not None


class TestPeerStatus:
    def _make_status(self):
        ctl = _make_ctl()
        peer = _make_peer()
        cohort = MagicMock(spec=CohortInterface)
        cohort.register_updater = MagicMock()
        cohort.browser_connected = 0
        mapp = MagicMock()
        parent = MagicMock()
        icons = {'drone': 'mdi:drone'}
        return PeerStatus(ctl, peer, cohort, mapp, parent, icons)

    def test_creation(self):
        ps = self._make_status()
        assert ps.fig is not None
        assert ps.net_figs == {}
        assert ps.trust_figs == {}

    def test_add_trust_gauge(self):
        ps = self._make_status()
        gauge = ps.add_trust_gauge(0)
        assert gauge is not None
        assert 0 in ps.trust_figs

    def test_add_trust_gauge_duplicate(self):
        ps = self._make_status()
        g1 = ps.add_trust_gauge(0)
        g2 = ps.add_trust_gauge(0)
        assert g1 is g2

    def test_add_net_graph(self):
        ps = self._make_status()
        ps.peer.network_history['other-1'] = deque()
        fig = ps.add_net_graph(0, 'other-1')
        assert fig is not None
        assert 0 in ps.net_figs

    def test_add_net_graph_duplicate(self):
        ps = self._make_status()
        ps.peer.network_history['other-1'] = deque()
        f1 = ps.add_net_graph(0, 'other-1')
        f2 = ps.add_net_graph(0, 'other-1')
        assert f1 is f2

    def test_update_summary_empty(self):
        ps = self._make_status()
        xes, y1s, y2s, y3s = ps.update_summary()
        assert isinstance(xes, list)
        assert isinstance(y3s, list)

    def test_peer_details(self):
        ps = self._make_status()
        d = ps.peer_details()
        assert d is not None

    def test_div_glance(self):
        ps = self._make_status()
        d = ps.div(glance=True)
        assert d is not None

    def test_div_glance_active(self):
        ps = self._make_status()
        d = ps.div(glance=True, active=True)
        assert d is not None

    def test_div_full(self):
        ps = self._make_status()
        d = ps.div(glance=False)
        assert d is not None

    def test_update_micrograph(self):
        ps = self._make_status()
        ps.update_micrograph()  # no browser connected, should be no-op

    def test_update_net_graphs(self):
        ps = self._make_status()
        ps.update_net_graphs()  # no others, should be no-op

    def test_populate_with_others(self):
        ps = self._make_status()
        ps.peer.network_history['other-1'] = deque()
        ps.populate()
        assert 0 in ps.net_figs
        assert 0 in ps.trust_figs
