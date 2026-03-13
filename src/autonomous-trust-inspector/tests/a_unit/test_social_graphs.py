import json

import pytest

try:
    from autonomous_trust.inspector.viz.network_graph import Graphs, NetworkGraph
    from autonomous_trust.inspector.viz.social_graphs import (
        DeceitNetwork, BetrayalNetwork, ReputationManipulationNetwork,
        SybilNetwork, CorruptAuthorityNetwork,
    )
    _has_deps = True
except (ImportError, ModuleNotFoundError):
    _has_deps = False

pytestmark = pytest.mark.skipif(not _has_deps, reason="networkx/aenum not installed")


class TestDeceitNetwork:
    def test_creation(self):
        dn = DeceitNetwork(8)
        assert dn.G is not None
        assert dn.iteration == 0
        assert dn.problem is not None

    def test_stop_after_20(self):
        dn = DeceitNetwork(8)
        assert dn.stop is False
        dn.iteration = 21
        assert dn.stop is True

    def test_change_sets_next_change(self):
        dn = DeceitNetwork(8)
        dn.change()
        assert dn.next_change == 3000
        dn.change()
        assert dn.next_change == 3000
        dn.change()
        assert 500 <= dn.next_change <= 2000

    def test_grouping_early(self):
        dn = DeceitNetwork(8)
        dn.iteration = 1
        dn.change_type = None
        dn.grouping()

    def test_grouping_after_iter_2(self):
        dn = DeceitNetwork(8)
        dn.iteration = 5
        dn.change_type = None
        dn.grouping()

    def test_problem_node_is_trouble(self):
        dn = DeceitNetwork(8)
        assert dn.G.nodes[dn.problem]['group'] == 'trouble'

    def test_registered(self):
        g = Graphs.get_graph('lies', 8)
        assert isinstance(g, DeceitNetwork)

    def test_get_update_cycle(self):
        dn = DeceitNetwork(8)
        for _ in range(5):
            next_t, data, stop = dn.get_update()
            if stop:
                break


class TestBetrayalNetwork:
    def test_creation(self):
        bn = BetrayalNetwork(8)
        assert bn.G is not None
        assert bn.iteration == 0
        assert bn.problem is not None
        assert bn.target is not None

    def test_stop_after_50(self):
        bn = BetrayalNetwork(8)
        assert bn.stop is False
        bn.iteration = 51
        assert bn.stop is True

    def test_change(self):
        bn = BetrayalNetwork(8)
        bn.change()
        assert 500 <= bn.next_change <= 2000
        assert bn.iteration == 1

    def test_grouping_phases(self):
        bn = BetrayalNetwork(8)
        for phase in [1, 5, 15, 25]:
            bn.iteration = phase
            bn.change_type = None
            bn.grouping()

    def test_problem_node_is_trouble(self):
        bn = BetrayalNetwork(8)
        assert bn.G.nodes[bn.problem]['group'] == 'trouble'

    def test_target_node_is_target(self):
        bn = BetrayalNetwork(8)
        assert bn.G.nodes[bn.target]['group'] == 'target'

    def test_registered(self):
        g = Graphs.get_graph('frenemy', 8)
        assert isinstance(g, BetrayalNetwork)


class TestReputationManipulationNetwork:
    def test_creation(self):
        rn = ReputationManipulationNetwork(8)
        assert rn.G is not None
        assert rn.iteration == 0
        assert rn.target is not None
        assert len(rn.clique) > 0

    def test_stop_after_50(self):
        rn = ReputationManipulationNetwork(8)
        assert rn.stop is False
        rn.iteration = 51
        assert rn.stop is True

    def test_change_phases(self):
        rn = ReputationManipulationNetwork(8)
        rn.change()  # iteration < 10; note: next_change overwritten by final randint
        assert 500 <= rn.next_change <= 3000

    def test_change_connect_phase(self):
        rn = ReputationManipulationNetwork(8)
        rn.iteration = 12
        rn.change()

    def test_grouping_phases(self):
        rn = ReputationManipulationNetwork(8)
        for phase in [1, 10, 16, 25]:
            rn.iteration = phase
            rn.change_type = None
            rn.grouping()

    def test_registered(self):
        g = Graphs.get_graph('clique', 8)
        assert isinstance(g, ReputationManipulationNetwork)


class TestSybilNetwork:
    def test_creation(self):
        sn = SybilNetwork(8)
        assert sn.G is not None
        assert sn.iteration == 0
        assert sn.target is not None
        assert len(sn.sybils) > 0

    def test_stop_after_30(self):
        sn = SybilNetwork(8)
        assert sn.stop is False
        sn.iteration = 31
        assert sn.stop is True

    def test_change_initial(self):
        sn = SybilNetwork(8)
        sn.change()
        assert sn.next_change == 15000

    def test_change_phases(self):
        sn = SybilNetwork(8)
        for i in range(7):
            sn.change()

    def test_grouping_phases(self):
        sn = SybilNetwork(8)
        for phase in [0, 2, 5]:
            sn.iteration = phase
            sn.change_type = None
            sn.grouping()

    def test_registered(self):
        g = Graphs.get_graph('sybil', 8)
        assert isinstance(g, SybilNetwork)


class TestCorruptAuthorityNetwork:
    def test_creation(self):
        cn = CorruptAuthorityNetwork(8)
        assert cn.G is not None
        assert cn.iteration == 0
        assert cn.problem is not None

    def test_stop_after_30(self):
        cn = CorruptAuthorityNetwork(8)
        assert cn.stop is False
        cn.iteration = 31
        assert cn.stop is True

    def test_change_initial(self):
        cn = CorruptAuthorityNetwork(8)
        cn.change()
        assert cn.iteration == 1

    def test_change_try_fail_phase(self):
        cn = CorruptAuthorityNetwork(8)
        for i in range(12):
            cn.change()

    def test_change_connect_level2_phase(self):
        cn = CorruptAuthorityNetwork(8)
        cn.iteration = 12
        cn.change()

    def test_grouping_phases(self):
        cn = CorruptAuthorityNetwork(8)
        for phase in [1, 10, 20]:
            cn.iteration = phase
            cn.change_type = None
            cn.grouping()

    def test_registered(self):
        g = Graphs.get_graph('captain', 8)
        assert isinstance(g, CorruptAuthorityNetwork)
