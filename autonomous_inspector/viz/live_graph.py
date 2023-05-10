import queue

import networkx as nx

from . import network_graph as ng


class LiveNetwork(ng.NetworkGraph):
    def __init__(self, _, **kwargs):
        self.node_data.append('persist')
        self.iteration = 0
        groups = ['a', '', ' ', 'trouble']
        super().__init__(nx.complete_graph, 1, delay=True, groups=groups, **kwargs)
        all_nodes = list(self.G)
        self.problem = all_nodes[0]
        self._start()
        self.wise = []
        self.data_q = kwargs['data_q']

    @property
    def stop(self):
        return False

    def get_update(self):
        try:
            data = self.data_q.get(block=True, timeout=0.01)
            # FIXME read node data. add to self.G.nodes
        except queue.Empty:
            pass
        return super().get_update()

    def _node_init(self, n):
        super()._node_init(n)
        for n in list(self.G):
            self.G.nodes[n]["group"] = self.groupLabels[0]

    def _post_init(self):
        super()._post_init()
        self.G.nodes[self.problem]["group"] = self.groupLabels[-1]
        self.G.nodes[self.problem]["persist"] = True

    def change(self):
        self.next_change = 1000

    def grouping(self):  # noqa
        if not super().grouping():
            return


ng.Graphs.register_implementation('live', LiveNetwork)
