import json
import random
from enum import Enum

import networkx as nx


class State(Enum):
    ADD = "add"
    REMOVE = "remove"


class NetworkGraph():
    initial_delay = 2000  # millisec
    debug = False

    def __init__(self, m1, m2):
        self.m1 = m1
        self.m2 = m2
        self._reset()

    def _reset(self):
        # arbitrary starting graph, could be any - including null
        self.G = nx.barbell_graph(self.m1, self.m2)
        self.change_type = None
        self.initialized = False
        self.next_change = self.initial_delay
        self.grouping()
        self._record_state()

    @property
    def node_ids(self):
        return list([n for n in self.G])

    @property
    def max_node_id(self):
        return max(self.node_ids)

    def _record_state(self):
        previous_state = self._to_dict(False)
        self.previous_nodes = previous_state['nodes']
        self.previous_links = previous_state['links']

    def change(self):
        raise NotImplementedError

    def grouping(self):
        raise NotImplementedError

    def renew(self):
        self._reset()

    def get_update(self):
        if self.initialized:
            self.change()
        if self.debug:
            print("Serve %sgraph data: %d nodes, %d links" %
                  ("full " if not self.initialized else "",
                   len(self._to_dict()["nodes"]),
                   len(self._to_dict()["links"])))
        data = str(self)
        self._record_state()
        self.initialized = True
        return self.next_change / 1000.0, data

        
    def nodeset_diff(self, s1, s2):
        node_diff = set([n['id'] for n in s1]) - set([n['id'] for n in s2])
        result = []
        for n in node_diff:
            for d in s1 + s2:
                if d['id'] == n:
                    result.append(d)
                    break
        return result

    def edgeset_diff(self, s1, s2):
        edge_diff = set([(e['source'], e['target']) for e in s1]) - set([(e['source'], e['target']) for e in s2])
        result = []
        for e in edge_diff:
            for d in s1 + s2:
                if d['source'] == e[0] and d['target'] == e[1]:
                    result.append(d)
                    break
        return result

    def _to_dict(self, track_change=True):
        # node-link format to serialize
        data_obj = nx.json_graph.node_link_data(self.G)
        if track_change and self.change_type is not None:
            data_obj['type'] = self.change_type.value.lower()
            if self.change_type == State.ADD:
                data_obj['nodes'] = self.nodeset_diff(data_obj['nodes'], self.previous_nodes)
                data_obj['links'] = self.edgeset_diff(data_obj['links'], self.previous_links)
            elif self.change_type == State.REMOVE:
                data_obj['nodes'] = self.nodeset_diff(self.previous_nodes, data_obj['nodes'])
                data_obj['links'] = self.edgeset_diff(self.previous_links, data_obj['links'])
        return data_obj

    def __str__(self):
        return json.dumps(self._to_dict())

    def to_file(self, filename):
        json.dump(self._to_dict(False), open(filename, "w"))


####################


class RandomNetwork(NetworkGraph):
    ## randomized behavior
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def _random_node(self, exclude=None):
        idx = random.randint(0, len(self.node_ids)-1)
        if idx == exclude:
            if exclude == 0:
                idx += 1
            else:
                idx -= 1
        return self.node_ids[idx]

    def _random_pair(self):
        n1 = self._random_node()
        n2 = self._random_node(n1)
        return n1, n2

    def change(self):
        r = random.randint(1, 100)
        if r < 20:
            node_num = self.max_node_id + 1
            self.change_type = State.ADD
            self.G.add_node(node_num)
        elif 20 < r < 70:
            self.change_type = State.ADD
            edge = self._random_pair()
            while self.G.has_edge(*edge):
                edge = self._random_pair()
            self.G.add_edge(*edge)
        elif r > 95:
            node_num = self._random_node()
            self.change_type = State.REMOVE
            self.G.remove_node(node_num)
        elif 70 < r < 95:
            self.change_type = State.REMOVE
            edge = self._random_pair()
            while not self.G.has_edge(*edge):
                edge = self._random_pair()
            self.G.remove_edge(*edge)
        self.grouping()
        self.next_change = random.randint(1, 2000)

    def grouping(self):
        for n in self.G:
            self.G.nodes[n]["name"] = n
            self.G.nodes[n]["group"] = random.randint(1, 6)
        for u, v, a in self.G.edges(data=True):
            src = self.G.nodes[u]
            tgt = self.G.nodes[v]
            a["group"] = src["group"] if src["group"] == tgt["group"] else 0
            a["value"] = random.randint(1, 10)
