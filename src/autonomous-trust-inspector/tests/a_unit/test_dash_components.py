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


def _net_stats(up=1.0, down=2.0, sent=10, recv=20):
    """A real NetworkStats, since the renderers read its named fields."""
    from autonomous_trust.services.network_statistics import NetworkStats
    return NetworkStats(up, down, sent, recv, 0, 0)


def _make_peer(uuid='uuid-1', index=0):
    ident = MagicMock()
    ident.nickname = 'Test Peer'
    ident.petname = 'TP'
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

    def test_an_aware_time_does_not_render_the_offset_beside_the_Z(self):
        """Cohort times are UTC-aware now, and the old
        `isoformat(' ').rsplit('.')[0]` had no '.' to cut on at microsecond=0, so
        the offset survived: '2024-06-15 12:00:00+00:00 Z'."""
        from datetime import timezone
        t = self._make_timer()
        t.cohort.time = datetime(2024, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        assert t._stamp(t.cohort.time) == '2024-06-15 12:00:00 Z'

    def test_a_non_utc_time_is_converted_not_relabelled(self):
        """Only UTC earns the Z the header prints."""
        from datetime import timedelta as _td, timezone
        t = self._make_timer()
        when = datetime(2024, 6, 15, 14, 0, 0, tzinfo=timezone(_td(hours=2)))
        assert t._stamp(when) == '2024-06-15 12:00:00 Z'

    def test_a_naive_time_still_renders(self):
        t = self._make_timer()
        assert t._stamp(datetime(2024, 6, 15, 12, 0, 0)) == '2024-06-15 12:00:00 Z'

    def test_the_stamp_reaches_the_browser(self):
        from datetime import timezone
        t = self._make_timer()
        t.ctl.push_mods = MagicMock()
        t.cohort.time = datetime(2024, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        t.update_time()
        assert t.ctl.push_mods.call_args.args[0]['time']['children'] == \
            ['2024-06-15 12:00:00 Z']


class TestDataFeed:
    def test_creation(self):
        ctl = _make_ctl()
        peer = _make_peer()
        df = DataFeed(ctl, peer, 0)
        assert df.fig is not None
        # No `halt`: the loop it guarded was never started by anything, and the
        # feed is now driven by the cohort tick (`PeerStatus.update_data_feed`).
        assert not hasattr(df, 'halt')
        assert df.fig.data == ()       # traces come from the first sample

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

    def test_update_summary_x_covers_every_sample(self):
        """Found while tracing the subplot bug: x was one shorter than y, and
        plotly drops the tail of the longer series -- so the micrograph silently
        hid the NEWEST sample, the one it exists to show."""
        ps = self._make_status()
        ps.peer.network_history['other-1'] = deque([_net_stats() for _ in range(3)])
        xes, y1s, y2s, y3s = ps.update_summary()
        assert len(xes) == len(y1s) == len(y2s) == 3

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


class TestPeerDetailPushes:
    """ISSUES §4.2: the trust/network subplots in the peer-detail drawer never
    populated. The figures were updated server-side on every cohort tick, but
    nothing told the browser: the push calls were commented out, guarded on
    `parent.displayed_detail` -- which `MapDisplay` sets to -1 and never touches
    again, so the guard could never become true.

    Two distinct failures, so two sets of tests: figures must reach the browser
    while the drawer is open, and a peer discovered AFTER the drawer opened
    needs its subplot divs created (a figure push cannot populate an id that is
    not in the DOM).
    """

    def _make_status(self, others=('other-1',), reputation=0.8):
        ctl = _make_ctl()
        peer = _make_peer()
        cohort = MagicMock(spec=CohortInterface)
        cohort.register_updater = MagicMock()
        cohort.browser_connected = 1
        for name in others:
            peer.network_history[name] = deque([_net_stats()])
        if reputation is not None:
            peer.reputation_history.append(reputation)
        ps = PeerStatus(ctl, peer, cohort, MagicMock(), MagicMock(),
                        {'drone': 'mdi:drone'})
        ps.ctl.push_mods = MagicMock()
        return ps

    @staticmethod
    def _pushed_ids(ps):
        ids = set()
        for call in ps.ctl.push_mods.call_args_list:
            ids.update(call.args[0].keys())
        return ids

    def test_trust_figure_reaches_the_browser_while_open(self):
        ps = self._make_status()
        ps.set_detail_open(True)
        ps.ctl.push_mods.reset_mock()
        ps.update_trust_levels()
        assert f'trust-{ps.idx}-0' in self._pushed_ids(ps)

    def test_net_figure_reaches_the_browser_while_open(self):
        ps = self._make_status()
        ps.set_detail_open(True)
        ps.ctl.push_mods.reset_mock()
        ps.update_net_graphs()
        assert f'net-graph-{ps.idx}-0' in self._pushed_ids(ps)

    def test_nothing_is_pushed_while_the_drawer_is_closed(self):
        """The whole point of the guard: 50 peers' hidden drawers must not each
        push a figure on every tick."""
        ps = self._make_status()
        ps.set_detail_open(False)
        ps.ctl.push_mods.reset_mock()
        ps.update_trust_levels()
        ps.update_net_graphs()
        assert self._pushed_ids(ps) == set()

    def test_nothing_is_pushed_with_no_browser_attached(self):
        ps = self._make_status()
        ps.set_detail_open(True)
        ps.cohort.browser_connected = 0
        ps.ctl.push_mods.reset_mock()
        ps.update_trust_levels()
        assert self._pushed_ids(ps) == set()

    def test_a_peer_discovered_after_opening_gets_its_subplot_divs(self):
        """A figure push cannot populate a div that does not exist, so the
        detail body has to be rebuilt when the set of others grows."""
        ps = self._make_status(others=('other-1',))
        ps.set_detail_open(True)
        ps.ctl.push_mods.reset_mock()
        ps.peer.network_history['other-2'] = deque([_net_stats()])
        ps.update_trust_levels()
        assert f'peer-detail-{ps.idx}' in self._pushed_ids(ps)
        assert 1 in ps.trust_figs        # the new other got a gauge

    def test_a_stable_roster_does_not_rebuild_the_body(self):
        """Rebuilding every tick would throw away the client's DOM for nothing."""
        ps = self._make_status(others=('other-1',))
        ps.set_detail_open(True)
        ps.ctl.push_mods.reset_mock()
        ps.update_trust_levels()
        ps.update_net_graphs()
        assert f'peer-detail-{ps.idx}' not in self._pushed_ids(ps)

    def test_trust_gauge_carries_the_reputation_value(self):
        ps = self._make_status(reputation=0.42)
        ps.set_detail_open(True)
        ps.update_trust_levels()
        assert ps.trust_figs[0].data[0].value == pytest.approx(0.42)


class TestPeerActiveTracksTheDrawer:
    """`peer.active` gates VideoFeed.xmit/rcv, so a drawer that closes must
    clear it -- otherwise the feed streams frames nobody is looking at."""

    def _make_status(self):
        cohort = MagicMock(spec=CohortInterface)
        cohort.register_updater = MagicMock()
        cohort.browser_connected = 1
        return PeerStatus(_make_ctl(), _make_peer(), cohort, MagicMock(),
                          MagicMock(), {'drone': 'mdi:drone'})

    def test_opening_marks_the_peer_active(self):
        ps = self._make_status()
        ps.set_detail_open(True)
        assert ps.peer.active is True

    def test_closing_clears_it(self):
        ps = self._make_status()
        ps.set_detail_open(True)
        ps.set_detail_open(False)
        assert ps.peer.active is False


class TestVideoFeedWaits:
    """I15. The feed's wait was `while len(stream) < 1: sleep(0.1)`, which spun,
    throttled a 30 fps source to 10 fps, and — decisively — could not run at all
    against the stream type production supplies: QueuePool hands out Queues, with
    neither __len__ nor pop, and the loop caught neither TypeError nor
    AttributeError.
    """

    def _feed(self, stream, active=True, paused=False):
        ctl = _make_ctl()
        peer = _make_peer()
        peer.video_stream = stream
        peer.cohort.paused = paused
        peer.active = active
        return VideoFeed(ctl, peer, 0)

    def test_a_queue_backed_stream_yields_a_frame(self):
        """The regression: a Queue has no __len__, so the old loop raised
        TypeError here and killed the feed."""
        from queue import Queue
        q = Queue()
        q.put((0, b'JPEGDATA', 1))
        assert self._feed(q)._next_frame() == b'JPEGDATA'

    def test_a_deque_backed_stream_still_works(self):
        feed = self._feed(deque([(0, b'JPEGDATA', 1)]))
        assert feed._next_frame() == b'JPEGDATA'

    def test_the_newest_frame_wins_over_a_backlog(self):
        """A live view showing a queued-up backlog would fall further behind."""
        from queue import Queue
        q = Queue()
        for i in range(4):
            q.put((i, b'frame-%d' % i, 1))
        assert self._feed(q)._next_frame() == b'frame-3'

    def test_a_paused_cohort_idles_without_consuming(self):
        from queue import Queue
        q = Queue()
        q.put((0, b'JPEGDATA', 1))
        feed = self._feed(q, paused=True)
        feed.wait_sec = 0.01
        assert feed._next_frame() is None
        assert q.qsize() == 1          # the frame is still there for later

    def test_an_inactive_peer_idles(self):
        from queue import Queue
        feed = self._feed(Queue(), active=False)
        feed.wait_sec = 0.01
        assert feed._next_frame() is None

    def test_an_empty_stream_idles_rather_than_raising(self):
        from queue import Queue
        feed = self._feed(Queue())
        feed.wait_sec = 0.01
        assert feed._next_frame() is None

    def test_a_frame_with_tobytes_is_converted(self):
        """Real frames are numpy arrays; the test doubles are bytes already."""
        from queue import Queue

        class _Arr:
            def tobytes(self):
                return b'CONVERTED'
        q = Queue()
        q.put((0, _Arr(), 1))
        assert self._feed(q)._next_frame() == b'CONVERTED'

    def test_the_wait_is_not_a_poll_interval(self):
        """wait_sec bounds shutdown latency, not throughput: a frame arriving
        mid-wait must return at once."""
        import threading as _t
        import time as _time
        from queue import Queue
        q = Queue()
        feed = self._feed(q)
        feed.wait_sec = 5.0
        _t.Timer(0.02, lambda: q.put((0, b'LATE', 1))).start()
        started = _time.monotonic()
        assert feed._next_frame() == b'LATE'
        assert _time.monotonic() - started < 1.0


def _find_by_id(component, target):
    """The rendered component carrying `target` as its id, or None.

    Walks `children` because the assertion that matters is what the BROWSER
    receives: a caption pushed to an id that the body never rendered lands
    nowhere, which is exactly how the subplot pushes failed before.
    """
    if getattr(component, 'id', None) == target:
        return component
    children = getattr(component, 'children', None)
    if children is None:
        return None
    if not isinstance(children, (list, tuple)):
        children = [children]
    for child in children:
        found = _find_by_id(child, target)
        if found is not None:
            return found
    return None


def _reported_metadata(lat=34.0, lon=-86.0, alt=100.0, data_type='video'):
    """Metadata as a peer that HAS reported carries it -- real PeerData, so the
    caption path runs against a real Position.convert."""
    from autonomous_trust.services.peer.metadata import PeerData
    from autonomous_trust.services.peer.position import GeoPosition
    return PeerData(datetime.now(), GeoPosition(lat, lon, alt), 0.0, 'drone',
                    data_type, 3)


class TestDetailCaptionsAreLive:
    """ISSUES §4.2:360. The drawer's captions were rendered once, when the body
    was built, and never updated: the position under the video feed froze at
    wherever the peer was when the drawer opened -- for a moving peer, the one
    value that panel exists to show. The data caption was worse than stale: it was
    built from a `data_type` copied in `__init__`, which runs while the peer still
    holds `NullPeerData`, so it read as the empty placeholder for the life of the
    component no matter what the peer later reported.
    """

    def _make_status(self, metadata=None):
        cohort = MagicMock(spec=CohortInterface)
        cohort.register_updater = MagicMock()
        cohort.browser_connected = 1
        peer = _make_peer()
        peer.metadata = metadata if metadata is not None else _reported_metadata()
        ps = PeerStatus(_make_ctl(), peer, cohort, MagicMock(), MagicMock(),
                        {'drone': 'mdi:drone'})
        ps.ctl.push_mods = MagicMock()
        return ps

    @staticmethod
    def _pushed(ps):
        """div id -> last pushed children, across every push_mods call."""
        out = {}
        for call in ps.ctl.push_mods.call_args_list:
            for div_id, mod in call.args[0].items():
                if 'children' in mod:
                    out[div_id] = mod['children']
        return out

    def test_position_caption_tracks_a_moving_peer(self):
        ps = self._make_status()
        ps.set_detail_open(True)
        ps.ctl.push_mods.reset_mock()
        ps.peer.metadata = _reported_metadata(lat=35.5, lon=-87.25, alt=250.0)
        ps.update_detail_titles()
        caption = self._pushed(ps).get(ps.vid_feed.title_id)
        assert caption is not None
        assert '35.5' in caption and '-87.25' in caption and '250' in caption

    def test_an_unchanged_caption_is_not_pushed_again(self):
        """A stationary peer must cost nothing: the drawer is open for as long as
        an operator is looking at it, and this runs on every tick."""
        ps = self._make_status()
        ps.set_detail_open(True)
        ps.ctl.push_mods.reset_mock()
        ps.update_detail_titles()
        ps.update_detail_titles()
        assert self._pushed(ps) == {}

    def test_nothing_is_pushed_while_the_drawer_is_closed(self):
        ps = self._make_status()
        ps.set_detail_open(False)
        ps.ctl.push_mods.reset_mock()
        ps.peer.metadata = _reported_metadata(lat=1.0, lon=2.0)
        ps.update_detail_titles()
        assert self._pushed(ps) == {}

    def test_nothing_is_pushed_with_no_browser_attached(self):
        ps = self._make_status()
        ps.set_detail_open(True)
        ps.cohort.browser_connected = 0
        ps.ctl.push_mods.reset_mock()
        ps.peer.metadata = _reported_metadata(lat=1.0, lon=2.0)
        ps.update_detail_titles()
        assert self._pushed(ps) == {}

    def test_the_data_caption_arrives_with_the_metadata(self):
        """The peer is rostered with NullPeerData, so at construct time there IS
        no data type; the old code captured that emptiness permanently."""
        from autonomous_trust.inspector.peer.daq import NullPeerData
        ps = self._make_status(metadata=NullPeerData())
        assert 'not yet reported' in ps._data_title()
        ps.set_detail_open(True)
        ps.ctl.push_mods.reset_mock()
        ps.peer.metadata = _reported_metadata(data_type='lidar')
        ps.update_detail_titles()
        assert self._pushed(ps).get(ps.data_feed.title_id) == 'lidar data'

    def test_data_type_is_read_live_not_captured(self):
        from autonomous_trust.inspector.peer.daq import NullPeerData
        ps = self._make_status(metadata=NullPeerData())
        ps.peer.metadata = _reported_metadata(data_type='sonar')
        assert ps.data_type == 'sonar'

    def test_an_unreported_position_reads_as_unreported(self):
        """NullPeerData holds a bare Position at (0, 0). Rendering that as a fix
        would be a lie an operator cannot tell from a real one off Africa."""
        from autonomous_trust.inspector.peer.daq import NullPeerData
        ps = self._make_status(metadata=NullPeerData())
        text = ps._position_text()
        assert text == 'position not yet reported'
        assert '0.000000' not in text

    def test_the_drawer_builds_for_a_peer_that_has_not_reported(self):
        """Regression: a bare Position raises NotImplementedError on convert, so
        full_div raised inside the Dash callback and built no body at all."""
        from autonomous_trust.inspector.peer.daq import NullPeerData
        ps = self._make_status(metadata=NullPeerData())
        body = ps.full_div()
        assert _find_by_id(body, ps.vid_feed.title_id) is not None

    def test_the_rendered_body_carries_the_current_caption(self):
        """Pushed text and rendered text come from one helper, so a rebuild can't
        disagree with a push."""
        ps = self._make_status()
        ps.peer.metadata = _reported_metadata(lat=12.5, lon=-13.75, alt=42.0)
        body = ps.full_div()
        title = _find_by_id(body, ps.vid_feed.title_id)
        assert '12.5' in title.children and '-13.75' in title.children
        assert _find_by_id(body, ps.data_feed.title_id).children == 'video data'

    def test_a_rebuild_reseeds_what_the_browser_has(self):
        """The body replaces the elements, so the cache has to follow it: stale
        entries would suppress a needed push, and missing ones would duplicate."""
        ps = self._make_status()
        ps.set_detail_open(True)          # renders the body
        ps.ctl.push_mods.reset_mock()
        ps.update_detail_titles()
        assert self._pushed(ps) == {}     # body already carried this text
        ps.peer.metadata = _reported_metadata(lat=44.0, lon=-99.0)
        ps.update_detail_titles()
        assert ps.vid_feed.title_id in self._pushed(ps)


class TestDataFeedRecords:
    """ISSUES §4.2:113 (data recording + rendering). The per-peer sensor plot had
    never worked, for four independent reasons, each measured rather than assumed:
    nothing ever called `rcv()` (no route, no thread, no caller), so
    `peer.data_stream` -- an unbounded pooled Queue the receiver keeps filing into
    -- was never drained; the update passed `x=`/`y=` INSIDE `selector=`, which
    patches nothing and matches no trace; the initial trace paired one x value
    with `data_channels` y values, a shape plotly cannot plot, and
    `data_channels` is 0 at construct time anyway (`NullPeerData`); and `div()`
    rendered the graph without its figure. Now driven by the cohort tick.
    """

    def _feed(self, stream=None, number=0):
        from queue import Queue
        ctl = _make_ctl()
        peer = _make_peer()
        peer.data_stream = stream if stream is not None else Queue()
        return DataFeed(ctl, peer, number)

    def test_a_sample_reaches_the_figure(self):
        from queue import Queue
        q = Queue()
        q.put([1.0, 2.0, 3.0])
        feed = self._feed(q)
        assert feed.drain() is True
        assert len(feed.fig.data) == 3                     # one trace per channel
        assert feed.fig.data[0].y == (1.0,)
        assert feed.fig.data[2].y == (3.0,)

    def test_traces_come_from_the_sample_not_from_metadata(self):
        """data_channels is 0 while the peer holds NullPeerData, so a figure built
        in __init__ had nothing usable to plot for the component's whole life."""
        from queue import Queue
        from autonomous_trust.inspector.peer.daq import NullPeerData
        q = Queue()
        q.put([1.0, 2.0])
        feed = self._feed(q)
        feed.peer.metadata = NullPeerData()
        assert feed.peer.metadata.data_channels == 0
        feed.drain()
        assert len(feed.fig.data) == 2

    def test_the_series_accumulates_in_order(self):
        from queue import Queue
        q = Queue()
        for value in (1.0, 2.0, 3.0):
            q.put([value])
        feed = self._feed(q)
        feed.drain()
        assert feed.fig.data[0].y == (1.0, 2.0, 3.0)
        assert feed.fig.data[0].x == (1.0, 2.0, 3.0)

    def test_x_and_y_are_the_same_length(self):
        """The old initial trace paired 1 x with N y, and plotly silently drops
        the tail of the longer series."""
        from queue import Queue
        q = Queue()
        for value in (1.0, 2.0):
            q.put([value, value * 2])
        feed = self._feed(q)
        feed.drain()
        for trace in feed.fig.data:
            assert len(trace.x) == len(trace.y)

    def test_a_scalar_sample_is_accepted(self):
        from queue import Queue
        q = Queue()
        q.put(4.5)
        feed = self._feed(q)
        feed.drain()
        assert feed.fig.data[0].y == (4.5,)

    def test_a_late_channel_is_back_filled_with_a_gap_not_a_zero(self):
        """A zero would read as a measurement."""
        from queue import Queue
        q = Queue()
        q.put([1.0])
        q.put([1.0, 9.0])
        feed = self._feed(q)
        feed.drain()
        assert feed.fig.data[1].y == (None, 9.0)

    def test_a_short_sample_leaves_a_gap(self):
        from queue import Queue
        q = Queue()
        q.put([1.0, 2.0])
        q.put([1.0])
        feed = self._feed(q)
        feed.drain()
        assert feed.fig.data[1].y == (2.0, None)

    def test_history_is_bounded(self):
        from queue import Queue
        q = Queue()
        feed = self._feed(q)
        feed.max_samples = 5
        feed._xes = deque(maxlen=5)
        for value in range(20):
            q.put([float(value)])
        feed.drain()
        assert len(feed.fig.data[0].y) == 5
        assert feed.fig.data[0].y[-1] == 19.0              # newest kept

    def test_an_empty_stream_reports_no_change(self):
        """So the caller can skip a push that would carry nothing."""
        assert self._feed().drain() is False

    def test_the_drain_is_bounded_per_tick(self):
        """A backlog must not stall the shared render loop."""
        from queue import Queue
        q = Queue()
        feed = self._feed(q)
        feed.max_per_tick = 3
        for value in range(10):
            q.put([float(value)])
        feed.drain()
        assert q.qsize() == 7

    def test_the_drain_does_not_block_on_an_empty_stream(self):
        """It runs on the shared tick, so it must not wait on one peer."""
        import time as _time
        started = _time.monotonic()
        self._feed().drain()
        assert _time.monotonic() - started < 0.5

    def test_the_graph_id_follows_the_drawer_not_the_peer_index(self):
        """peer.index is not unique across roster churn, and a duplicate DOM id
        breaks the page rather than merely confusing it."""
        feed = self._feed(number=7)
        feed.peer.index = 3
        assert feed.graph_id == 'data_graph_7'

    def test_the_rendered_graph_carries_the_figure(self):
        from queue import Queue
        q = Queue()
        q.put([1.0])
        feed = self._feed(q)
        feed.drain()
        graph = _find_by_id(feed.div('title'), feed.graph_id)
        assert graph is not None
        assert graph.figure is feed.fig


class TestDataFeedRendersWhenWatched:
    """The recording half is useless if nothing tells the browser -- the same
    break as the trust/net subplots (§4.2:279)."""

    def _make_status(self, samples=((1.0, 2.0, 3.0),)):
        from queue import Queue
        cohort = MagicMock(spec=CohortInterface)
        cohort.register_updater = MagicMock()
        cohort.browser_connected = 1
        peer = _make_peer()
        peer.data_stream = Queue()
        for sample in samples:
            peer.data_stream.put(list(sample))
        ps = PeerStatus(_make_ctl(), peer, cohort, MagicMock(), MagicMock(),
                        {'drone': 'mdi:drone'})
        ps.ctl.push_mods = MagicMock()
        return ps

    @staticmethod
    def _pushed_ids(ps):
        ids = set()
        for call in ps.ctl.push_mods.call_args_list:
            ids.update(call.args[0].keys())
        return ids

    def test_the_plot_reaches_the_browser_while_open(self):
        ps = self._make_status()
        ps.set_detail_open(True)
        ps.ctl.push_mods.reset_mock()
        ps.update_data_feed()
        assert ps.data_feed.graph_id in self._pushed_ids(ps)

    def test_nothing_is_pushed_while_the_drawer_is_closed(self):
        ps = self._make_status()
        ps.set_detail_open(False)
        ps.ctl.push_mods.reset_mock()
        ps.update_data_feed()
        assert self._pushed_ids(ps) == set()

    def test_the_stream_is_drained_even_while_closed(self):
        """Nothing else consumes data_stream: skipping the drain would lose the
        history the drawer exists to show AND grow an unbounded queue."""
        ps = self._make_status()
        ps.set_detail_open(False)
        ps.update_data_feed()
        assert ps.peer.data_stream.empty()
        assert ps.data_feed.fig.data[0].y == (1.0,)

    def test_an_idle_tick_pushes_nothing(self):
        ps = self._make_status(samples=())
        ps.set_detail_open(True)
        ps.ctl.push_mods.reset_mock()
        ps.update_data_feed()
        assert self._pushed_ids(ps) == set()

    def test_nothing_is_pushed_with_no_browser_attached(self):
        ps = self._make_status()
        ps.set_detail_open(True)
        ps.cohort.browser_connected = 0
        ps.ctl.push_mods.reset_mock()
        ps.update_data_feed()
        assert self._pushed_ids(ps) == set()
