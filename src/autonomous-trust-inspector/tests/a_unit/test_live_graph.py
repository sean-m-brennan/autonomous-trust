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
from collections import namedtuple

import pytest

try:
    import networkx as nx
    from autonomous_trust.inspector.viz.live_graph import LiveData, LiveNetwork
    from autonomous_trust.inspector.viz.network_graph import Graphs
    _has_deps = True
except (ImportError, ModuleNotFoundError):
    _has_deps = False

pytestmark = pytest.mark.skipif(not _has_deps, reason="networkx/aenum not installed")

_Rep = namedtuple('_Rep', ['peer_id', 'score'])


class TestLiveData:
    def test_class_attributes(self):
        assert LiveData.peers == 'peers'
        assert LiveData.reputation == 'reputation'
        assert LiveData.latencies == 'latencies'
        assert LiveData.commands == 'commands'

    # --- None-graph / malformed payloads must be safe no-ops ---
    def test_run_data_handlers_none_graph(self):
        for which in (LiveData.peers, LiveData.reputation,
                      LiveData.latencies, LiveData.commands):
            LiveData.run_data_handlers(None, which, {})       # must not raise
        LiveData.run_data_handlers(None, LiveData.peers, 42)  # non-iterable

    # --- peers: ensure a node per uuid, keyed by uuid ---
    def test_peers_creates_nodes(self):
        g = nx.Graph()
        LiveData.run_data_handlers(g, LiveData.peers, {'noaa-1': {}, 'noaa-2': {}})
        assert g.has_node('noaa-1') and g.has_node('noaa-2')
        assert g.graph['uuid_nodes'] == {'noaa-1': 'noaa-1', 'noaa-2': 'noaa-2'}

    # --- reputation: direct rep object -> node attr ---
    def test_reputation_direct_sets_node_attr(self):
        g = nx.Graph()
        LiveData.run_data_handlers(g, LiveData.reputation, _Rep('noaa-1', 0.8))
        assert g.nodes['noaa-1']['reputation'] == 0.8

    # --- reputation: transitive triple -> per-observer edge trust (asymmetric) ---
    def test_reputation_transitive_sets_edge_trust(self):
        g = nx.Graph()
        LiveData.run_data_handlers(g, LiveData.reputation, ('noaa-1', 'noaa-2', 0.9))
        LiveData.run_data_handlers(g, LiveData.reputation, ('noaa-2', 'noaa-1', 0.3))
        # One undirected edge carries both directional views.
        assert g.edges['noaa-1', 'noaa-2']['trust'] == {'noaa-1': 0.9, 'noaa-2': 0.3}
        # ...and a scalar summary (worst-case) for rendering/diffing.
        assert g.edges['noaa-1', 'noaa-2']['trust_level'] == 0.3

    def test_latencies_and_commands(self):
        g = nx.Graph()
        LiveData.run_data_handlers(g, LiveData.latencies, ('noaa-1', 12.5))
        LiveData.run_data_handlers(g, LiveData.commands, ('noaa-1', 'halt'))
        assert g.nodes['noaa-1']['latency'] == 12.5
        assert g.nodes['noaa-1']['command'] == 'halt'


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
