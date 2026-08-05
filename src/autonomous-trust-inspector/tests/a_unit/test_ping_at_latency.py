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
"""A PingAT reply must reach the display.

Both consumers were fed only mocks before, so both were broken in ways a
"a message arrived" assertion cannot see: the bridge called float() on a
PingATStats (TypeError, caught, skipped) and the inspector forwarded the raw
object into a channel whose handler ignores anything that is not a 2-tuple.
Every test here builds a REAL PingATStats and checks the value that lands.
"""

import queue
import sys
from datetime import timedelta
from unittest.mock import MagicMock

import pytest

# inspector.py pulls in viz.server, which imports quart at module level and uses
# it only inside methods. These tests exercise the PingAT consumers, not the web
# server, so a stub stands in when quart is absent.
#
# Everything needed is imported HERE, under the stub, and then both the stub and
# every inspector module it let through are dropped from sys.modules. The
# references below keep working, while a later test module that legitimately
# needs quart re-imports, fails, and skips as it did before -- leaving a cached
# mock-backed viz.server behind turned those skips into failures.
_stubbed_quart = 'quart' not in sys.modules
_before = set(sys.modules)
if _stubbed_quart:
    sys.modules['quart'] = MagicMock()
try:
    from autonomous_trust.core._python.network.ping_at import PingATStats
    from autonomous_trust.core.network import Network
    from autonomous_trust.inspector.inspector import Inspector, _replied_uuid
    from autonomous_trust.inspector.bridge import InspectorBridge
    from autonomous_trust.inspector.latency import LatencySample, summarize
    from autonomous_trust.inspector.viz.live_graph import LiveData
    has_inspector = True
except (ImportError, ModuleNotFoundError):
    has_inspector = False
finally:
    if _stubbed_quart:
        sys.modules.pop('quart', None)
        # Only the quart-touching modules go: viz.server and the two that import
        # it. The viz graph modules stay cached deliberately -- social_graphs
        # builds aenum members at import, and a second import raises
        # "'LIES' already in use as property".
        for _name in ('autonomous_trust.inspector.viz.server',
                      'autonomous_trust.inspector.inspector',
                      'autonomous_trust.inspector.bridge'):
            if _name in sys.modules and _name not in _before:
                del sys.modules[_name]
                # The sys.modules entry is not the only handle: importing a
                # submodule also BINDS it on its parent package, and
                # `from ...viz import server` reads that attribute without
                # consulting sys.modules at all. Dropping one and not the other
                # handed test_viz the mock-backed module and turned its skips
                # into two failures.
                _parent, _, _leaf = _name.rpartition('.')
                _pkg = sys.modules.get(_parent)
                if _pkg is not None and hasattr(_pkg, _leaf):
                    delattr(_pkg, _leaf)

pytestmark = pytest.mark.skipif(not has_inspector,
                                reason='inspector dependencies not available')


def _stats(host='10.0.0.7', times=(0.010, 0.012, 0.014), lost=0):
    """A real PingATStats, built the way ping_at() builds one."""
    mapping = {i: t for i, t in enumerate(times)}
    for j in range(lost):
        mapping[len(mapping)] = None
    return PingATStats(host, mapping,
                       timedelta(seconds=sum(times) + lost))


class _Peer:
    def __init__(self, uuid='uuid-noaa-1', nickname='noaa-1@tekfive.com'):
        self.uuid = uuid
        self.nickname = nickname
        self.petname = None
        self.signature = None


def _reply(stats, peer=None):
    """A PingAT reply shaped as netprocess._do_ping_at_async builds it."""
    msg = MagicMock()
    msg.function = Network.ping_at
    msg.obj = stats
    msg.from_whom = peer if peer is not None else _Peer()
    msg.to_whom = []
    return msg


# --- the conversion itself -------------------------------------------------

class TestSummarize:
    def test_real_stats_summarize_to_numbers(self):
        s = summarize(_stats(times=(0.010, 0.020, 0.030)))
        assert isinstance(s, LatencySample)
        assert s.rtt_ms == pytest.approx(20.0)   # average of 10/20/30 ms
        assert s.loss_pct == pytest.approx(0.0)
        assert s.count == 3

    def test_loss_is_carried_not_hidden(self):
        # One answer in five: the average alone looks perfectly healthy.
        s = summarize(_stats(times=(0.010,), lost=4))
        assert s.rtt_ms == pytest.approx(10.0)
        assert s.loss_pct == pytest.approx(80.0)
        assert s.count == 5

    def test_float_of_stats_is_a_typeerror(self):
        # The exact failure the old bridge code hit and swallowed.
        with pytest.raises(TypeError):
            float(_stats())

    def test_non_stats_is_none_not_a_crash(self):
        assert summarize(None) is None
        assert summarize(12.5) is None
        assert summarize('nope') is None

    def test_empty_round_is_not_a_sample(self):
        # `loss` divides by len(times); an empty round would raise.
        assert summarize(PingATStats('h', {}, timedelta(0))) is None


# --- inspector: (uuid, rtt_ms) onto the latencies channel ------------------

def _inspector_stub(messages, ticks=(False, False, True)):
    """An Inspector with just enough shape to run autonomous_tasking's
    5-second branch (tick 2) and nothing else."""
    insp = MagicMock(spec=Inspector)
    insp.data_queue = queue.Queue()
    insp.unhandled_messages = list(messages)
    insp.latest_reputation = {}
    insp.latest_reputation_pairs = {}
    insp.tasking_tick = MagicMock(side_effect=lambda n, *a: n == 2)
    insp.autonomous_tasking = Inspector.autonomous_tasking.__get__(insp)
    return insp


class TestInspectorConsumer:
    def test_latency_lands_as_the_two_tuple_the_graph_requires(self):
        insp = _inspector_stub([_reply(_stats(times=(0.010, 0.020, 0.030)))])
        insp.autonomous_tasking({})

        channel, payload = insp.data_queue.get_nowait()
        assert channel == LiveData.latencies
        assert isinstance(payload, tuple) and len(payload) == 2
        uuid, rtt_ms = payload
        assert uuid == 'uuid-noaa-1'
        assert rtt_ms == pytest.approx(20.0)
        # ...and the graph actually applies it, which the raw object never did.
        import networkx as nx
        g = nx.Graph()
        LiveData.run_data_handlers(g, channel, payload)
        assert g.nodes['uuid-noaa-1']['latency'] == pytest.approx(20.0)

    def test_raw_stats_object_would_be_ignored_by_the_graph(self):
        # Pins WHY the fix was needed: the old payload reaches the handler and
        # changes nothing, so "a message arrived" proved nothing.
        import networkx as nx
        g = nx.Graph()
        LiveData.run_data_handlers(g, LiveData.latencies, _stats())
        assert len(g.nodes) == 0

    def test_reply_is_consumed_from_unhandled(self):
        insp = _inspector_stub([_reply(_stats())])
        insp.autonomous_tasking({})
        assert insp.unhandled_messages == []

    def test_unusable_stats_push_nothing(self):
        msg = _reply(_stats())
        msg.obj = 'not stats'
        insp = _inspector_stub([msg])
        insp.autonomous_tasking({})
        with pytest.raises(queue.Empty):
            insp.data_queue.get_nowait()

    def test_reply_naming_nobody_pushes_nothing(self):
        msg = _reply(_stats(), peer=object())    # no .uuid
        msg.to_whom = []
        insp = _inspector_stub([msg])
        insp.autonomous_tasking({})
        with pytest.raises(queue.Empty):
            insp.data_queue.get_nowait()

    def test_replied_uuid_unwraps_a_list(self):
        msg = _reply(_stats(), peer=None)
        msg.from_whom = None
        msg.to_whom = [_Peer(uuid='uuid-x')]
        assert _replied_uuid(msg) == 'uuid-x'


# --- bridge: ("ping_at", name, rtt_ms, loss_pct, count, wall_t) ------------

class TestBridgeConsumer:
    def _bridge_stub(self, messages):
        br = MagicMock()                       # unspecced: the method reads
        br.unhandled_messages = list(messages)  # several attrs off self
        br.latest_reputation = {}
        br.latest_reputation_pairs = {}
        br._last_pair = {}
        br._seen = set()
        br.peers = MagicMock(all=[])
        br.peer_capabilities = None
        pushed = []
        br._push = pushed.append
        br.pushed = pushed
        br.tasking_tick = MagicMock(side_effect=lambda n, *a: n == 2)
        br.autonomous_tasking = InspectorBridge.autonomous_tasking.__get__(br)
        return br

    def test_ping_at_event_carries_rtt_loss_and_count(self):
        br = self._bridge_stub([_reply(_stats(times=(0.010,), lost=4))])
        br.autonomous_tasking({})

        assert len(br.pushed) == 1
        tag, name, rtt_ms, loss_pct, count, wall_t = br.pushed[0]
        assert tag == 'ping_at'
        assert name == 'noaa-1'              # '@domain' stripped
        assert rtt_ms == pytest.approx(10.0)
        assert loss_pct == pytest.approx(80.0)
        assert count == 5
        assert wall_t > 0

    def test_unusable_stats_push_nothing(self):
        msg = _reply(_stats())
        msg.obj = 3.14                        # what float() used to accept
        br = self._bridge_stub([msg])
        br.autonomous_tasking({})
        assert br.pushed == []

    def test_reply_is_consumed_from_unhandled(self):
        br = self._bridge_stub([_reply(_stats())])
        br.autonomous_tasking({})
        assert br.unhandled_messages == []


# --- the evaluation timeline reads the same tag ----------------------------

def _playback_interface():
    """PlaybackInterface, with the evaluation package put on the path.

    The inspector conftest adds only autonomous-trust and -services, so the
    evaluation sibling has to be located here.
    """
    import os
    root = os.path.abspath(os.path.join(os.path.dirname(__file__),
                                        '..', '..', '..'))
    pkg = os.path.join(root, 'autonomous-trust-evaluation')
    if os.path.isdir(pkg) and pkg not in sys.path:
        sys.path.insert(0, pkg)
    try:
        from autonomous_trust.evaluation.scenarios.playback_iface import (
            PlaybackInterface)
    except (ImportError, ModuleNotFoundError):
        pytest.skip('evaluation package not available')
    return PlaybackInterface


class TestPlaybackAnnotation:
    """The evaluation timeline reads the bridge's tag, so it renamed too."""

    def _drain(self, event):
        cls = _playback_interface()
        pb = MagicMock()
        pb._bridge_queue = queue.Queue()
        pb._bridge_queue.put(event)
        pb._bridge_seen = set()
        pb._bridge_event_handlers = []
        pb._fire_bridge_event = MagicMock()
        pb._fire_event_log = MagicMock()
        log = []
        pb._scenario = MagicMock(_event_log=log)
        pb._drain_bridge = cls._drain_bridge.__get__(pb)
        pb._drain_bridge(1.0)
        return log

    def test_ping_at_is_annotated(self):
        log = self._drain(('ping_at', 'noaa-1', 12.5, 0.0, 5, 1.0))
        assert len(log) == 1
        assert 'noaa-1 rtt = 12ms' in log[0]['description']   # %.0f, ties down
        assert 'loss' not in log[0]['description']   # clean round, no noise

    def test_loss_is_annotated_when_present(self):
        log = self._drain(('ping_at', 'noaa-1', 10.0, 80.0, 5, 1.0))
        assert 'loss = 80%' in log[0]['description']

    def test_old_tag_no_longer_matches(self):
        # Nothing should still be emitting "ping"; if something does, the
        # timeline must not silently annotate it as if the rename never
        # happened.
        assert self._drain(('ping', 'noaa-1', 12.5, 1.0)) == []
