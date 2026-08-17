# ******************
#  Copyright 2023 TekFive, Inc., Sean M. Brennan, and contributors
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
        """Fold one live-data event into the networkx graph ``graph`` (the
        ``.G`` of a NetworkGraph).

        Peers are keyed into the graph by uuid via a ``graph.graph['uuid_nodes']``
        map (uuid -> node key). Nodes carry a ``reputation`` attribute (this
        observer's direct trust of the peer); **transitive** (peer-of-peer)
        trust is stored per-observer on the connecting edge's ``trust`` dict so
        an asymmetric A->B vs B->A view is preserved on the undirected edge.

        Data shapes by label:
          - ``peers``:      dict/iterable of peer uuids -> ensure a node per uuid
          - ``reputation``: a rep object with ``.peer_id``/``.score`` (direct
                            trust -> node attr), or an
                            ``(observer_uuid, subject_uuid, score)`` triple
                            (transitive trust -> edge attr)
          - ``latencies``:  ``(peer_uuid, rtt)`` -> node ``latency`` attr
          - ``commands``:   ``(peer_uuid, text)`` -> node ``command`` annotation

        A ``None`` graph or unrecognized/malformed ``data`` is a safe no-op so a
        partially-wired producer can never crash the render loop.
        """
        if graph is None:
            return
        if which == cls.peers:
            cls._ensure_peer_nodes(graph, data)
        elif which == cls.reputation:
            cls._apply_reputation(graph, data)
        elif which == cls.latencies:
            cls._apply_latency(graph, data)
        elif which == cls.commands:
            cls._apply_command(graph, data)

    @staticmethod
    def _peer_node(graph, uuid):
        """Return the graph node key for ``uuid``, creating the node (keyed by
        the uuid string itself) on first sight."""
        mapping = graph.graph.setdefault('uuid_nodes', {})
        node = mapping.get(uuid)
        if node is None:
            node = uuid
            mapping[uuid] = node
            if not graph.has_node(node):
                graph.add_node(node, name=uuid, id=uuid, group=None, reputation=None)
        return node

    @classmethod
    def _ensure_peer_nodes(cls, graph, data):
        if not data:
            return
        uuids = data.keys() if isinstance(data, dict) else data
        try:
            for uuid in uuids:
                cls._peer_node(graph, uuid)
        except TypeError:
            pass  # data not iterable — ignore malformed payload

    @classmethod
    def _apply_reputation(cls, graph, data):
        # Transitive (observer, subject, score) triple -> per-observer edge trust.
        if isinstance(data, (tuple, list)) and len(data) == 3:
            observer, subject, score = data
            o = cls._peer_node(graph, observer)
            s = cls._peer_node(graph, subject)
            graph.add_edge(o, s)
            trust = graph.edges[o, s].setdefault('trust', {})
            trust[observer] = score
            # Scalar summary for rendering/diffing (dicts aren't hashable and
            # can't be styled directly): worst-case of the directional views.
            graph.edges[o, s]['trust_level'] = min(trust.values())
            return
        # Direct: a rep object with .peer_id / .score -> node reputation attr.
        peer_id = getattr(data, 'peer_id', None)
        if peer_id is not None:
            node = cls._peer_node(graph, peer_id)
            graph.nodes[node]['reputation'] = getattr(data, 'score', None)

    @classmethod
    def _apply_latency(cls, graph, data):
        if isinstance(data, (tuple, list)) and len(data) == 2:
            uuid, rtt = data
            graph.nodes[cls._peer_node(graph, uuid)]['latency'] = rtt

    @classmethod
    def _apply_command(cls, graph, data):
        if isinstance(data, (tuple, list)) and len(data) == 2:
            uuid, text = data
            graph.nodes[cls._peer_node(graph, uuid)]['command'] = text


class LiveNetwork(ng.NetworkGraph):
    cadence_ms = 1000

    def __init__(self, _, **kwargs):
        # Track reputation (node) + trust_level (edge) in the diff keys so a
        # change in transitive trust triggers an update emit to the client.
        # `latency` and `command` belong here for the same reason and were
        # missed: a frame's node set is a diff over `node_data` ONLY, so an
        # attribute absent from this list can change every tick without ever
        # producing a difference to emit. Both channels reach the graph
        # (`_apply_latency`, `_apply_command`) and both stopped at the server
        # for any peer already known -- a PingAT sample updated a node the
        # client was never told about again.
        self.node_data = list(self.node_data) + ['persist', 'reputation',
                                                 'latency', 'command']
        self.link_data = list(self.link_data) + ['trust_level']
        self.iteration = 0
        self._stopped = False
        groups = ['a', '', ' ', 'trouble']
        self.data_q = kwargs.pop('data_q')
        super().__init__(nx.complete_graph, 1, delay=True, groups=groups, **kwargs)
        all_nodes = list(self.G)
        self.problem = all_nodes[0]
        self._start()
        self.wise = []

    @property
    def stop(self):
        return self._stopped

    def shutdown(self):
        """Signal the live network to stop on the next update cycle."""
        self._stopped = True

    def get_update(self):
        try:
            label, data = self.data_q.get(block=True, timeout=queue_cadence)
            if label is None:
                # Sentinel value signals disconnect
                self._stopped = True
            else:
                LiveData.run_data_handlers(self.G, label, data)
        except queue.Empty:
            pass
        return super().get_update()

    def _node_init(self, n):
        super()._node_init(n)
        for node in list(self.G):
            self.G.nodes[node]["group"] = self.groupLabels[0]

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
