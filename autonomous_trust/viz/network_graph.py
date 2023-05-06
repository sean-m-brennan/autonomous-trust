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
    link_data = ['source', 'target', 'group', 'weight']
    default_groups = 'a b c d e f g h i j'.split(' ')
    maximum_weight = 10

    class PhaseChange(enum.Enum):
        NEW = 'new'
        ADD = "add"
        REMOVE = "remove"
        META = 'meta'

    def __init__(self, generator, *args, debug=False, groups=None, delay=False, **kwargs):
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
        self.__reset(delay)
        self.__backlog = []

    def __reset(self, delay=False):
        # arbitrary starting graph, could be any - including null
        self.G = self.graph_gen(*self.args, **self.kwargs)
        self.change_type = self.PhaseChange.NEW
        self.initialized = False
        self.next_change = self.initial_delay
        if not delay:
            self._start()

    def _node_init(self, n):
        self.G.nodes[n]["name"] = n
        idx = random.randint(1, len(self.groupLabels)-1)
        self.G.nodes[n]["group"] = self.groupLabels[idx]

    def _post_init(self):
        self.propagate_node_grouping()

    def _start(self):
        for n in self.G:
            self._node_init(n)
        self._post_init()
        self.grouping()
        self._record_state()

    @staticmethod
    def identity(g):
        return lambda _: g

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

    def grouping(self, defaults=True):
        if self.change_type in [self.PhaseChange.ADD, self.PhaseChange.REMOVE]:
            return False
        if self.change_type is None:
            self.change_type = self.PhaseChange.META
        if defaults:
            for u, v, a in self.G.edges(data=True):
                if "weight" not in a:
                    a["weight"] = random.randint(1, self.maximum_weight)
        return True

    @staticmethod
    def _hierarchy_gen(size, num_levels, with_links=True):
        levels = []
        g = None
        sizes = [0]
        for lev in range(1, num_levels+1):
            sizes.append(lev * size // num_levels)
        for lev in range(1, num_levels+1):
            level_graph = nx.complete_graph(range(sizes[lev-1], sizes[lev]))
            if lev == 1:
                g = level_graph
            else:
                g = nx.compose(g, level_graph)
            level_nodes = list(level_graph)
            level_head = level_nodes[0]
            if lev > 1 and with_links:
                for n in levels[lev-2]:
                    g.add_edge(n, level_head)
            levels.append(level_nodes)
        return g, levels

    def propagate_node_grouping(self):
        for u, v, a in self.G.edges(data=True):
            src = self.G.nodes[u]
            tgt = self.G.nodes[v]
            if "group" in src and "group" in tgt:
                a["group"] = src["group"] if src["group"] == tgt["group"] else 0

    def renew(self):
        self.__reset()

    @property
    def stop(self):
        return False

    def get_update(self):
        if len(self.__backlog) > 0:
            last = None
            while len(self.__backlog) > 0:
                if last is not None and self.__backlog[0][1] != last:
                    break
                tpl = self.__backlog.pop(0)
                if tpl[1] == 'add_node':
                    self.add_node()
                    last = self.PhaseChange.ADD
                elif tpl[1] == 'add_edge':
                    self.add_edge(*tpl[2:])
                    last = self.PhaseChange.ADD
                elif tpl[1] == 'remove_node':
                    self.remove_node(tpl[2])
                    last = self.PhaseChange.ADD
                elif tpl[1] == 'remove_edge':
                    self.remove_edge(*tpl[2:])
                    last = self.PhaseChange.ADD
        else:
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
        data = None
        if self.change_type is not None:
            data = str(self)
            self._record_state()
            self.initialized = True
        next_update = self.next_change / 1000.0
        if len(self.__backlog) > 0:
            next_update = 1 / 1000.0
        self.change_type = None
        return next_update, data, self.stop

    def add_node(self):
        if self.change_type not in [None, self.PhaseChange.ADD]:
            self.__backlog.append((self.PhaseChange.ADD, 'add_node',))
            return None
        node_num = self.max_node_id + 1
        self.change_type = self.PhaseChange.ADD
        self.G.add_node(node_num)
        return node_num

    def add_edge(self, u, v):
        if self.change_type not in [None, self.PhaseChange.ADD]:
            self.__backlog.append((self.PhaseChange.ADD, 'add_edge', u, v))
            return
        self.change_type = self.PhaseChange.ADD
        if not self.G.has_edge(u, v):
            self.G.add_edge(u, v)

    def remove_node(self, node_num):
        if self.change_type not in [None, self.PhaseChange.REMOVE]:
            self.__backlog.append((self.PhaseChange.REMOVE, 'remove_node', node_num))
            return
        self.change_type = self.PhaseChange.REMOVE
        self.G.remove_node(node_num)

    def remove_edge(self, u, v):
        if self.change_type not in [None, self.PhaseChange.REMOVE]:
            self.__backlog.append((self.PhaseChange.REMOVE, 'remove_edge', u, v))
            return
        self.change_type = self.PhaseChange.REMOVE
        if self.G.has_edge(u, v):
            self.G.remove_edge(u, v)

    def prune_edges(self):
        edge_list = []
        for u, v, a in self.G.edges(data=True):
            if "weight" in a and a["weight"] <= 0:
                edge_list.append((u, v))
        if self.debug and len(edge_list) > 0:
            print("Prune %d edges" % len(edge_list))
        for edge in edge_list:
            self.remove_edge(*edge)

    def _random_node(self, limit_to=None, exclude=None):
        if limit_to is None or len(limit_to) == 0:
            limit_to = self.node_ids
        if exclude is None:
            exclude = []
        elif not isinstance(exclude, list):
            exclude = [exclude]
        limit_to = list(set(limit_to) - set(exclude))
        idx = random.randint(0, len(limit_to)-1)
        return limit_to[idx]

    def _random_pair(self, limit_to=None):
        n1 = self._random_node(limit_to=limit_to)
        n2 = self._random_node(limit_to=limit_to, exclude=n1)
        return n1, n2

    def node_addition_rejected(self):  # noqa
        return False

    def node_removal_rejected(self, n):  # noqa
        return False

    def link_addition_limit(self):  # noqa
        return None

    def link_addition_rejected(self, u, v):  # noqa
        return False
    
    def link_removal_rejected(self, u, v):  # noqa
        return False

    def random_change(self, add_nodes=20, add_edges=80, remove_edges=95, persist=False, groups=True):
        r = random.randint(1, 100)
        if r <= add_nodes:
            if not self.node_addition_rejected():
                node_num = self.add_node()
                self.G.nodes[node_num]["group"] = self.groupLabels[random.randint(0, len(self.groupLabels))-1]
                self.G.nodes[node_num]["persist"] = persist
        elif add_nodes < r <= add_edges:
            if len(self.G) > 1:
                # FIXME prefer nodes from the same group
                edge = self._random_pair(limit_to=self.link_addition_limit())
                while self.G.has_edge(*edge) and self.link_addition_rejected(*edge):
                    edge = self._random_pair(limit_to=self.link_addition_limit())
                self.add_edge(*edge)
                self.propagate_node_grouping()
                self.G[edge[0]][edge[1]]["weight"] = random.randint(1, self.maximum_weight)
        elif add_edges < r <= remove_edges:
            if len(self.G.edges) > 2:
                edge = self._random_pair()
                while not self.G.has_edge(*edge) and self.link_removal_rejected(*edge):
                    edge = self._random_pair()
                self.remove_edge(*edge)
        elif r > remove_edges:
            if len(self.G) > 1:
                node_num = self._random_node()
                if not self.node_removal_rejected(node_num):
                    self.remove_node(node_num)

    def node_metadata(self, nodeset):
        return set([tuple([n[k] for k in self.node_data if k in n]) for n in nodeset])

    def edge_metadata(self, edgeset):
        return set([tuple([e[k] for k in self.link_data if k in e]) for e in edgeset])

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
    def __init__(self, size, persist=False, speed=50, **kwargs):
        self.node_data.append('persist')
        m1 = size // 2
        super().__init__(nx.barbell_graph, m1, 0, **kwargs)
        self.persist = persist
        self.speed = speed
        for n in self.G:
            self.G.nodes[n]["persist"] = persist

    def change(self):
        self.random_change(persist=self.persist, groups=True)
        if self.speed is None:
            self.next_change = random.randint(100, 500)
        else:
            self.next_change = self.speed


Graphs.register_implementation('random', RandomNetwork, True)
