# ******************
#  Copyright 2024 TekFive, Inc. and contributors
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

import networkx as nx
from autonomous_trust.core.util import ClassEnumMeta
from autonomous_trust.core.system import queue_cadence

from . import network_graph as ng


class LiveData(object, metaclass=ClassEnumMeta):
    peers = 'peers'
    reputation = 'reputation'
    latencies = 'latencies'
    commands = 'commands'

    @classmethod
    def run_data_handlers(cls, graph, which, data):
        # FIXME read node data. add to self.G.nodes
        if which == cls.peers:
            pass
        elif which == cls.reputation:
            pass
        elif which == cls.latencies:
            pass
        elif which == cls.commands:
            pass


class LiveNetwork(ng.NetworkGraph):
    cadence_ms = 1000

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
            label, data = self.data_q.get(block=True, timeout=queue_cadence)
            LiveData.run_data_handlers(self.G, label, data)
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
        self.next_change = self.cadence_ms

    def grouping(self):  # noqa
        if not super().grouping():
            return


ng.Graphs.register_implementation('live', LiveNetwork)
