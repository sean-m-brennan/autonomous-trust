import queue

import pytest

from autonomous_trust.inspector.viz.live_graph import LiveData, LiveNetwork
from autonomous_trust.inspector.viz.network_graph import Graphs


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
