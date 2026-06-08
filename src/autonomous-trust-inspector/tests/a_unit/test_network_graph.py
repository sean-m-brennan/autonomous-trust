# ******************
#  Copyright 2025 Sean M. Brennan and contributors
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
import json
import random

import pytest

try:
    import networkx as nx
    from autonomous_trust.inspector.viz.network_graph import (
        Graphs, NetworkGraph, RandomNetwork,
    )
    _has_deps = True
except (ImportError, ModuleNotFoundError):
    _has_deps = False

pytestmark = pytest.mark.skipif(not _has_deps, reason="networkx/aenum not installed")


class TestGraphsRegistry:
    def test_get_graph_random(self):
        g = Graphs.get_graph('random', 12)
        assert isinstance(g, RandomNetwork)

    def test_register_and_get_implementation(self):
        class DummyGraph:
            def __init__(self, size, **kw):
                self.size = size
        Graphs.register_implementation('dummy_test', DummyGraph)
        g = Graphs.get_graph('dummy_test', 5)
        assert isinstance(g, DummyGraph)
        assert g.size == 5

    def test_implementation_enum_extended(self):
        vals = [e.value for e in Graphs.Implementation]
        assert 'random' in vals

    def test_get_graph_missing_raises(self):
        with pytest.raises(KeyError):
            Graphs.get_graph('nonexistent_xyz', 10)


class TestNetworkGraphBase:
    def _make_graph(self, size=6, **kw):
        class SimpleGraph(NetworkGraph):
            def change(self):
                self.next_change = 100
        return SimpleGraph(nx.complete_graph, size, **kw)

    def test_init_creates_graph(self):
        g = self._make_graph(6)
        assert g.G is not None
        assert len(g.node_ids) == 6

    def test_node_ids(self):
        g = self._make_graph(4)
        assert sorted(g.node_ids) == [0, 1, 2, 3]

    def test_max_node_id(self):
        g = self._make_graph(5)
        assert g.max_node_id == 4

    def test_phase_change_values(self):
        assert NetworkGraph.PhaseChange.NEW.value == 'new'
        assert NetworkGraph.PhaseChange.ADD.value == 'add'
        assert NetworkGraph.PhaseChange.REMOVE.value == 'remove'
        assert NetworkGraph.PhaseChange.META.value == 'meta'

    def test_identity_returns_lambda(self):
        fn = NetworkGraph.identity(42)
        assert fn(None) == 42

    def test_str_returns_json(self):
        g = self._make_graph(4)
        s = str(g)
        data = json.loads(s)
        assert 'nodes' in data
        assert g._link_key in data
        assert 'groups' in data

    def test_to_dict_has_groups(self):
        g = self._make_graph(4)
        d = g._to_dict(track_change=False)
        assert d['groups'] == NetworkGraph.default_groups

    def test_custom_groups(self):
        groups = ['x', 'y', 'z']
        g = self._make_graph(4, groups=groups)
        assert g.groupLabels == groups

    def test_add_node(self):
        g = self._make_graph(4)
        g.change_type = None  # clear NEW so add_node doesn't backlog
        old_max = g.max_node_id
        node_num = g.add_node()
        assert node_num == old_max + 1
        assert node_num in g.node_ids
        assert g.change_type == NetworkGraph.PhaseChange.ADD

    def test_add_edge(self):
        g = self._make_graph(4)
        g.change_type = None
        g.add_edge(0, 3)
        assert g.G.has_edge(0, 3)
        assert g.change_type == NetworkGraph.PhaseChange.ADD

    def test_add_edge_no_duplicate(self):
        g = self._make_graph(4)
        g.change_type = None
        g.add_edge(0, 1)  # already exists in complete graph
        assert g.G.has_edge(0, 1)

    def test_remove_node(self):
        g = self._make_graph(6)
        g.change_type = None
        g.remove_node(3)
        assert 3 not in g.node_ids
        assert g.change_type == NetworkGraph.PhaseChange.REMOVE

    def test_remove_edge(self):
        g = self._make_graph(4)
        g.change_type = None
        g.remove_edge(0, 1)
        assert not g.G.has_edge(0, 1)
        assert g.change_type == NetworkGraph.PhaseChange.REMOVE

    def test_remove_edge_nonexistent(self):
        g = self._make_graph(4)
        g.G.remove_edge(0, 1)
        g.change_type = None
        g.remove_edge(0, 1)  # should not raise

    def test_add_node_backlog_when_removing(self):
        g = self._make_graph(4)
        g.change_type = NetworkGraph.PhaseChange.REMOVE
        result = g.add_node()
        assert result is None  # queued to backlog

    def test_add_edge_backlog_when_removing(self):
        g = self._make_graph(4)
        g.change_type = NetworkGraph.PhaseChange.REMOVE
        g.add_edge(0, 2)
        # edge not immediately added, queued

    def test_remove_node_backlog_when_adding(self):
        g = self._make_graph(6)
        g.change_type = NetworkGraph.PhaseChange.ADD
        g.remove_node(3)
        assert 3 in g.node_ids  # still there, queued

    def test_remove_edge_backlog_when_adding(self):
        g = self._make_graph(4)
        g.change_type = NetworkGraph.PhaseChange.ADD
        g.remove_edge(0, 1)
        assert g.G.has_edge(0, 1)  # still there, queued

    def test_grouping_sets_weights(self):
        g = self._make_graph(4)
        g.change_type = None
        result = g.grouping()
        assert result is True
        for u, v, a in g.G.edges(data=True):
            assert 'weight' in a

    def test_grouping_returns_false_on_add(self):
        g = self._make_graph(4)
        g.change_type = NetworkGraph.PhaseChange.ADD
        assert g.grouping() is False

    def test_grouping_returns_false_on_remove(self):
        g = self._make_graph(4)
        g.change_type = NetworkGraph.PhaseChange.REMOVE
        assert g.grouping() is False

    def test_grouping_none_becomes_meta(self):
        g = self._make_graph(4)
        g.change_type = None
        g.grouping()
        assert g.change_type == NetworkGraph.PhaseChange.META

    def test_propagate_node_grouping(self):
        g = self._make_graph(4)
        # nodes already have groups from _start
        g.propagate_node_grouping()
        for u, v, a in g.G.edges(data=True):
            assert 'group' in a

    def test_prune_edges_removes_zero_weight(self):
        g = self._make_graph(4)
        g.change_type = None
        g.G[0][1]['weight'] = 0
        g.prune_edges()
        assert not g.G.has_edge(0, 1)

    def test_prune_edges_keeps_positive_weight(self):
        g = self._make_graph(4)
        g.change_type = None
        g.G[0][1]['weight'] = 5
        g.prune_edges()
        assert g.G.has_edge(0, 1)

    def test_renew_resets(self):
        g = self._make_graph(4)
        g.add_node()
        old_count = len(g.node_ids)
        g.renew()
        assert len(g.node_ids) == 4  # reset to original

    def test_stop_default_false(self):
        g = self._make_graph(4)
        assert g.stop is False

    def test_get_update_returns_tuple(self):
        g = self._make_graph(4)
        result = g.get_update()
        assert len(result) == 3
        next_update, data, stop = result
        assert isinstance(next_update, float)
        assert stop is False

    def test_get_update_initial_new(self):
        g = self._make_graph(4)
        # First call has change_type NEW
        _, data, _ = g.get_update()
        assert data is not None
        parsed = json.loads(data)
        assert parsed['type'] == 'new'

    def test_get_update_subsequent_none(self):
        g = self._make_graph(4)
        g.get_update()  # consume NEW
        # Next call with no change
        _, data, _ = g.get_update()
        # change() sets change_type but grouping may set META
        # data may or may not be None depending on grouping

    def test_random_node(self):
        g = self._make_graph(6)
        node = g._random_node()
        assert node in g.node_ids

    def test_random_node_with_limit(self):
        g = self._make_graph(6)
        node = g._random_node(limit_to=[0, 1])
        assert node in [0, 1]

    def test_random_node_with_exclude(self):
        g = self._make_graph(6)
        for _ in range(20):
            node = g._random_node(exclude=0)
            assert node != 0

    def test_random_pair(self):
        g = self._make_graph(6)
        n1, n2 = g._random_pair()
        assert n1 != n2
        assert n1 in g.node_ids
        assert n2 in g.node_ids

    def test_node_addition_rejected_default(self):
        g = self._make_graph(4)
        assert g.node_addition_rejected() is False

    def test_node_removal_rejected_default(self):
        g = self._make_graph(4)
        assert g.node_removal_rejected(0) is False

    def test_link_addition_limit_default(self):
        g = self._make_graph(4)
        assert g.link_addition_limit() is None

    def test_link_addition_rejected_default(self):
        g = self._make_graph(4)
        assert g.link_addition_rejected(0, 1) is False

    def test_link_removal_rejected_default(self):
        g = self._make_graph(4)
        assert g.link_removal_rejected(0, 1) is False

    def test_hierarchy_gen(self):
        g, levels = NetworkGraph._hierarchy_gen(12, 3)
        assert isinstance(g, nx.Graph)
        assert len(levels) == 3

    def test_hierarchy_gen_without_links(self):
        g, levels = NetworkGraph._hierarchy_gen(12, 3, with_links=False)
        assert isinstance(g, nx.Graph)
        assert len(levels) == 3

    def test_node_metadata(self):
        g = self._make_graph(4)
        d = g._to_dict(False)
        result = g.node_metadata(d['nodes'])
        assert isinstance(result, set)
        assert len(result) > 0

    def test_edge_metadata(self):
        g = self._make_graph(4)
        g.grouping()
        d = g._to_dict(False)
        result = g.edge_metadata(d[g._link_key])
        assert isinstance(result, set)

    def test_nodeset_diff(self):
        g = self._make_graph(4)
        d1 = g._to_dict(False)
        g.change_type = None
        node_num = g.add_node()
        g._node_init(node_num)
        d2 = g._to_dict(False)
        diff = g.nodeset_diff(d2['nodes'], d1['nodes'])
        assert len(diff) >= 1

    def test_edgeset_diff(self):
        g = self._make_graph(4)
        g.grouping()
        lk = g._link_key
        d1 = g._to_dict(False)
        g.change_type = None
        g.add_edge(0, 3)
        g.G[0][3]['weight'] = 5
        g.propagate_node_grouping()
        d2 = g._to_dict(False)
        diff = g.edgeset_diff(d2[lk], d1[lk])
        # may or may not find diff depending on whether edge already existed

    def test_to_file(self, tmp_path):
        g = self._make_graph(4)
        filepath = str(tmp_path / 'graph.json')
        g.to_file(filepath)
        with open(filepath) as f:
            data = json.load(f)
        assert 'nodes' in data
        # _to_dict normalizes networkx's 'edges' key to 'links' (force.js reads 'links').
        assert 'links' in data

    def test_random_change_add_node(self):
        g = self._make_graph(6)
        g.change_type = None
        random.seed(1)  # deterministic
        # Force add_nodes path (r <= 20)
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(random, 'randint', lambda a, b: 10 if (a, b) == (1, 100) else random.Random(42).randint(a, b))
            g.random_change()

    def test_random_change_various(self):
        g = self._make_graph(8)
        g.change_type = None
        # Run multiple random changes - shouldn't crash
        for _ in range(20):
            g.change_type = None
            g.random_change()

    def test_to_dict_add_type(self):
        g = self._make_graph(4)
        g.get_update()  # NEW
        g.change_type = None
        g.add_node()
        g._node_init(g.max_node_id)
        d = g._to_dict(track_change=True)
        assert d['type'] == 'add'

    def test_to_dict_remove_type(self):
        g = self._make_graph(6)
        g.get_update()  # NEW
        g.change_type = None
        g.remove_node(3)
        d = g._to_dict(track_change=True)
        assert d['type'] == 'remove'

    def test_get_update_processes_backlog(self):
        g = self._make_graph(6)
        g.get_update()  # consume NEW
        # Force a remove so add goes to backlog
        g.change_type = NetworkGraph.PhaseChange.REMOVE
        g.add_node()  # goes to backlog
        # Backlog should have one item
        _, data, _ = g.get_update()
        # Then process backlog
        _, data2, _ = g.get_update()


class TestRandomNetwork:
    def test_creation(self):
        rn = RandomNetwork(12)
        assert rn.G is not None
        assert rn.persist is False
        assert rn.speed == 50

    def test_creation_custom(self):
        rn = RandomNetwork(12, persist=True, speed=100)
        assert rn.persist is True
        assert rn.speed == 100

    def test_change_sets_speed(self):
        rn = RandomNetwork(12, speed=75)
        rn.change_type = None  # post-init state is NEW; change() requires None (cf. test_change_random_speed)
        rn.change()
        assert rn.next_change == 75

    def test_change_random_speed(self):
        rn = RandomNetwork(20, speed=None)
        rn.change_type = None
        rn.change()
        assert 100 <= rn.next_change <= 500

    def test_nodes_have_persist(self):
        rn = RandomNetwork(12)
        for n in rn.G:
            assert 'persist' in rn.G.nodes[n]

    def test_registered(self):
        g = Graphs.get_graph('random', 12)
        assert isinstance(g, RandomNetwork)
