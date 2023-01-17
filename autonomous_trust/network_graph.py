import json
import random
import enum

import networkx as nx
import aenum


class Graphs(object):
    class Implementation(aenum.Enum):
        DEFAULT = ''

    _MAP = {}

    @classmethod
    def get_graph(cls, name, size, debug=False):
        return cls._MAP[name](size, debug=debug)

    @classmethod
    def register_implementation(cls, name, impl_cls, is_default=False):
        aenum.extend_enum(cls.Implementation, name.upper(), name.lower())
        cls._MAP[name.lower()] = impl_cls
        if is_default:
            cls._MAP[cls.Implementation.DEFAULT.value] = impl_cls


####################


class NetworkGraph(object):
    """
    Abstract base class for dynamic network graphs
    """
    initial_delay = 2000  # milliseconds
    node_data = ['id', 'group']
    link_data = ['source', 'target', 'group', 'value']
    default_groups = 'a b c d e f g h i j'.split(' ')

    class PhaseChange(enum.Enum):
        META = 'meta'
        ADD = "add"
        REMOVE = "remove"

    def __init__(self, generator, *args, debug=False, groups=None, **kwargs):
        self.graph_gen = generator
        self.args = args
        self.debug = debug
        self.groupLabels = self.default_groups if groups is None else groups
        self.groups_len = len(self.groupLabels)
        self.kwargs = kwargs
        self.G = None
        self.change_type = None
        self.initialized = False
        self.next_change = 0
        self._reset()

    def _reset(self):
        # arbitrary starting graph, could be any - including null
        self.G = self.graph_gen(*self.args, **self.kwargs)
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
                print("Serve graph data: %d nodes, %d links" %
                      (len(self._to_dict()["nodes"]),
                       len(self._to_dict()["links"])))
        elif self.debug:
            print("Serve full graph data: %d nodes, %d links" %
                  (len(self.node_ids), len(self.G.edges)))
        self.grouping()
        self.prune_edges()
        data = str(self)
        self._record_state()
        self.initialized = True
        return self.next_change / 1000.0, data

    def add_node(self):
        node_num = self.max_node_id + 1
        self.change_type = self.PhaseChange.ADD
        self.G.add_node(node_num)
        return node_num

    def add_edge(self, u, v):
        self.change_type = self.PhaseChange.ADD
        if not self.G.has_edge(u, v):
            self.G.add_edge(u, v)

    def remove_node(self, node_num):
        self.change_type = self.PhaseChange.REMOVE
        self.G.remove_node(node_num)

    def remove_edge(self, u, v):
        self.change_type = self.PhaseChange.REMOVE
        if self.G.has_edge(u, v):
            self.G.remove_edge(u, v)

    def prune_edges(self):
        edge_list = []
        for u, v, a in self.G.edges(data=True):
            if "value" in a.keys() and a["value"] <= 0:
                edge_list.append((u, v))
        for edge in edge_list:
            self.remove_edge(*edge)

    def _random_node(self, limit_to=None, exclude=None):
        if limit_to is None or len(limit_to) == 0:
            limit_to = self.node_ids
        if exclude is None:
            exclude = []
        elif not isinstance(exclude, list):
            exclude = [exclude]
        idx = random.randint(0, len(limit_to)-1)
        if idx in exclude:
            if exclude == 0:
                idx += 1
            else:
                idx -= 1
        return limit_to[idx]

    def _random_pair(self, limit_to=None):
        n1 = self._random_node(limit_to=limit_to)
        n2 = self._random_node(limit_to=limit_to, exclude=n1)
        return n1, n2

    def node_removal_rejected(self, n):
        return False

    def link_addition_limit(self):
        return None

    def link_addition_rejected(self, u, v):
        return False
    
    def link_removal_rejected(self, u, v):
        return False

    def random_change(self, an=5, ae=80, re=95):
        r = random.randint(1, 100)
        if r < an:
            self.add_node()
        elif an < r < ae:
            edge = self._random_pair(limit_to=self.link_addition_limit())
            while self.G.has_edge(*edge) and self.link_addition_rejected(*edge):
                edge = self._random_pair()
            self.add_edge(*edge)
        elif r > re:
            node_num = self._random_node()
            if not self.node_removal_rejected(node_num):
                self.remove_node(node_num)
        elif ae < r < re:
            edge = self._random_pair()
            while not self.G.has_edge(*edge) and self.link_removal_rejected(*edge):
                edge = self._random_pair()
            self.remove_edge(*edge)

    def node_metadata(self, nodeset):
        return set([tuple([n[k] for k in self.node_data if k in n.keys()]) for n in nodeset])

    def edge_metadata(self, edgeset):
        return set([tuple([e[k] for k in self.link_data if k in e.keys()]) for e in edgeset])

    def nodeset_diff(self, s1, s2):
        node_diff = self.node_metadata(s1) - self.node_metadata(s2)
        result = []
        for n in node_diff:
            for d in s2 + s1:
                if d['id'] == n[self.node_data.index('id')]:
                    result.append(d)
                    break
        return result

    def edgeset_diff(self, s1, s2):
        edge_diff = self.edge_metadata(s1) - self.edge_metadata(s2)
        result = []
        for e in edge_diff:
            for d in s2 + s1:
                if d['source'] == e[self.link_data.index('source')] and \
                   d['target'] == e[self.link_data.index('target')]:
                    result.append(d)
                    break
        return result

    def _to_dict(self, track_change=True):
        # node-link format to serialize
        data_obj = nx.json_graph.node_link_data(self.G)
        data_obj['groups'] = self.groupLabels
        if track_change and self.change_type is not None:
            data_obj['type'] = self.change_type.value.lower()
            if self.change_type == self.PhaseChange.ADD:
                data_obj['nodes'] = self.nodeset_diff(data_obj['nodes'],
                                                      self.previous_nodes)
                data_obj['links'] = self.edgeset_diff(data_obj['links'],
                                                      self.previous_links)
            elif self.change_type == self.PhaseChange.REMOVE:
                data_obj['nodes'] = self.nodeset_diff(self.previous_nodes,
                                                      data_obj['nodes'])
                data_obj['links'] = self.edgeset_diff(self.previous_links,
                                                      data_obj['links'])
            elif self.change_type == self.PhaseChange.META:
                data_obj['nodes'] = self.nodeset_diff(self.previous_nodes,
                                                      data_obj['nodes'])
                data_obj['links'] = self.edgeset_diff(self.previous_links,
                                                      data_obj['links'])
        return data_obj

    def __str__(self):
        return json.dumps(self._to_dict())

    def to_file(self, filename):
        json.dump(self._to_dict(False), open(filename, "w"))


####################


class RandomNetwork(NetworkGraph):
    # randomized behavior
    def __init__(self, size, **kwargs):
        m1 = size // 2
        super().__init__(nx.barbell_graph, m1, 0, **kwargs)

    def change(self):
        self.random_change()
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


Graphs.register_implementation('random', RandomNetwork, True)
