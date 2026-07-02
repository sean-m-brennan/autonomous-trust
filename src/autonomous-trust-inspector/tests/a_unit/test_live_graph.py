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
import queue

import pytest

try:
    from autonomous_trust.inspector.viz.live_graph import LiveData, LiveNetwork
    from autonomous_trust.inspector.viz.network_graph import Graphs
    _has_deps = True
except (ImportError, ModuleNotFoundError):
    _has_deps = False

pytestmark = pytest.mark.skipif(not _has_deps, reason="networkx/aenum not installed")


class TestLiveData:
    def test_class_attributes(self):
        assert LiveData.peers == 'peers'
        assert LiveData.reputation == 'reputation'
        assert LiveData.latencies == 'latencies'
        assert LiveData.commands == 'commands'

    def test_run_data_handlers_peers(self):
        # Should not raise
        LiveData.run_data_handlers(None, LiveData.peers, {})

    def test_run_data_handlers_reputation(self):
        LiveData.run_data_handlers(None, LiveData.reputation, {})

    def test_run_data_handlers_latencies(self):
        LiveData.run_data_handlers(None, LiveData.latencies, {})

    def test_run_data_handlers_commands(self):
        LiveData.run_data_handlers(None, LiveData.commands, {})


class TestLiveNetwork:
    def test_creation(self):
        q = queue.Queue()
        ln = LiveNetwork(12, data_q=q)
        assert ln.G is not None
        assert ln.data_q is q

    def test_stop_always_false(self):
        q = queue.Queue()
        ln = LiveNetwork(12, data_q=q)
        assert ln.stop is False

    def test_change_sets_cadence(self):
        q = queue.Queue()
        ln = LiveNetwork(12, data_q=q)
        ln.change()
        assert ln.next_change == LiveNetwork.cadence_ms

    def test_get_update_empty_queue(self):
        q = queue.Queue()
        ln = LiveNetwork(12, data_q=q)
        next_t, data, stop = ln.get_update()
        assert stop is False

    def test_get_update_with_data(self):
        q = queue.Queue()
        ln = LiveNetwork(12, data_q=q)
        q.put((LiveData.peers, {'peer1': {}}))
        next_t, data, stop = ln.get_update()
        assert stop is False

    def test_grouping(self):
        q = queue.Queue()
        ln = LiveNetwork(12, data_q=q)
        ln.change_type = None
        ln.grouping()

    def test_registered(self):
        q = queue.Queue()
        g = Graphs.get_graph('live', 12, data_q=q)
        assert isinstance(g, LiveNetwork)

    def test_problem_node_trouble(self):
        q = queue.Queue()
        ln = LiveNetwork(12, data_q=q)
        assert ln.G.nodes[ln.problem]['group'] == 'trouble'
        assert ln.G.nodes[ln.problem]['persist'] is True
