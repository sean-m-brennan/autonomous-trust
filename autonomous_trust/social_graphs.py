import random
import networkx as nx

from . import network_graph as ng


class DeceitNetwork(ng.NetworkGraph):
    def __init__(self, size, **kwargs):
        self.node_data.append('persist')
        self.iteration = 0
        groups = ['a', '', ' ', 'trouble']
        super().__init__(nx.complete_graph, size - 1, delay=True, groups=groups, **kwargs)
        all_nodes = list(self.G)
        self.problem = all_nodes[0]
        self._start()
        self.wise = []

    @property
    def stop(self):
        return self.iteration > 20

    def _node_init(self, n):
        super()._node_init(n)
        for n in list(self.G):
            self.G.nodes[n]["group"] = self.groupLabels[0]

    def _post_init(self):
        super()._post_init()
        self.G.nodes[self.problem]["group"] = self.groupLabels[-1]
        self.G.nodes[self.problem]["persist"] = True

    def change(self):
        if self.iteration < 2:
            self.next_change = 3000
        else:
            self.next_change = random.randint(500, 2000)
        self.grouping()
        self.iteration += 1

    def grouping(self):  # noqa
        if not super().grouping():
            return
        for u, v, a in self.G.edges(data=True):
            if self.iteration > 2:
                all_nodes = list(self.G)
                available = set(all_nodes) - set([all_nodes[0]] + self.wise)
                if len(available) > 0:
                    r_node = list(available)[random.randint(0, len(available)-1)]
                    self.wise.append(r_node)
                if u == self.problem or v == self.problem:
                    for n in self.wise:
                        if u == n or v == n:
                            a["weight"] -= 1


ng.Graphs.register_implementation('lies', DeceitNetwork)


class BetrayalNetwork(ng.NetworkGraph):
    def __init__(self, size, **kwargs):
        self.iteration = 0
        groups = ['a', '', 'target', 'trouble']
        super().__init__(nx.complete_graph, size - 1, delay=True, groups=groups, **kwargs)
        all_nodes = list(self.G)
        self.problem = all_nodes[1]
        self.target = all_nodes[0]
        self._start()

    @property
    def stop(self):
        return self.iteration > 50

    def _node_init(self, n):
        super()._node_init(n)
        for n in list(self.G):
            self.G.nodes[n]["group"] = self.groupLabels[0]

    def _post_init(self):
        super()._post_init()
        self.G.nodes[self.problem]["group"] = self.groupLabels[-1]
        self.G.nodes[self.target]["group"] = self.groupLabels[-2]

    def change(self):
        self.next_change = random.randint(500, 2000)
        self.grouping()
        self.iteration += 1

    def grouping(self):  # noqa
        if not super().grouping():
            return
        for u, v, a in self.G.edges(data=True):
            if u in [self.target, self.problem] and v in [self.target, self.problem]:
                if 2 < self.iteration < 10:
                    a["weight"] += 1
                elif self.iteration > 20:
                    a["weight"] -= 2
            else:
                a["weight"] = random.randint(1, self.maximum_weight)


ng.Graphs.register_implementation('frenemy', BetrayalNetwork)


class ReputationManipulationNetwork(ng.NetworkGraph):
    def __init__(self, size, **kwargs):
        self.iteration = 0
        groups = 'a b target trouble'.split(' ')
        num_levels = 2
        g, levels = self._hierarchy_gen(size*num_levels, num_levels)
        self.orig = lambda _: nx.Graph(g)
        self.levels = levels
        super().__init__(self.orig, size*levels, delay=True, groups=groups, **kwargs)
        all_nodes = list(self.G)
        end = size - 5
        self.clique = all_nodes[:end]
        self.target = all_nodes[end]
        self._start()

    @property
    def stop(self):
        return self.iteration > 50

    def _node_init(self, n):
        super()._node_init(n)
        for idx, level in enumerate(self.levels):
            if n in level:
                self.G.nodes[n]["group"] = self.groupLabels[idx]
                break

    def _post_init(self):
        super()._post_init()
        for s in self.clique:
            self.G.nodes[s]["group"] = self.groupLabels[-1]
        self.G.nodes[self.target]["group"] = self.groupLabels[-2]

    def change(self):
        if self.iteration < 10:
            self.next_change = 3000
        elif self.iteration < 15:  # connect to level 2
            self.change_type = self.PhaseChange.ADD
            current = (self.target, self._random_node(limit_to=self.levels[1]))
            self.add_edge(*current)
            self.G[current[0]][current[1]]["group"] = 0
            self.G[current[0]][current[1]]["weight"] = 1
            self.next_change = 3000
        self.next_change = random.randint(500, 2000)
        self.grouping()
        self.iteration += 1

    def grouping(self):  # noqa
        if not super().grouping():
            return
        for u, v, a in self.G.edges(data=True):
            if u in self.clique and v in self.clique:
                a["weight"] = random.randint(5, self.maximum_weight)  # remain together
            elif (u in self.clique or v in self.clique) and \
                    (u == self.target or v == self.target):
                if self.iteration > 15:
                    if a["weight"] > 0:
                        a["weight"] -= 1
                else:
                    a["weight"] = random.randint(3, self.maximum_weight-3)
            elif u == self.target or v == self.target:
                if self.iteration < 2 or self.iteration > 15:
                    a["weight"] = random.randint(1, self.maximum_weight)
                else:
                    if a["weight"] > 1:
                        a["weight"] -= 1
            else:
                a["weight"] = random.randint(1, self.maximum_weight)


ng.Graphs.register_implementation('clique', ReputationManipulationNetwork)


class SybilNetwork(ng.NetworkGraph):
    def __init__(self, size, **kwargs):
        self.iteration = 0
        groups = 'a b target trouble'.split(' ')
        num_levels = 2
        g, levels = self._hierarchy_gen(size*num_levels, num_levels)
        self.orig = lambda _: nx.Graph(g)
        self.levels = levels
        super().__init__(self.orig, size*levels, delay=True, groups=groups, **kwargs)
        end = size - 1
        all_nodes = list(self.G)
        self.sybils = all_nodes[:end]
        self.target = all_nodes[end]
        self.assist = all_nodes[end + 2]
        self._start()

    @property
    def stop(self):
        return self.iteration > 30

    def _node_init(self, n):
        super()._node_init(n)
        for idx, level in enumerate(self.levels):
            if n in level:
                self.G.nodes[n]["group"] = self.groupLabels[idx]
                break

    def _post_init(self):
        super()._post_init()
        for s in self.sybils:
            self.G.nodes[s]["group"] = self.groupLabels[-1]
        self.G.nodes[self.target]["group"] = self.groupLabels[-2]

    def change(self):
        if self.iteration == 0:
            self.next_change = 15000
        elif self.iteration == 2:
            self.change_type = self.PhaseChange.ADD
            self.add_edge(self.target, self.assist)
            self.G[self.target][self.assist]["group"] = 0
            self.next_change = 3000
        elif self.iteration < 6:
            self.next_change = 3000
        else:
            self.next_change = random.randint(500, 2000)
        self.grouping()
        self.iteration += 1

    def grouping(self):  # noqa
        if not super().grouping(False):
            return
        for u, v, a in self.G.edges(data=True):
            if u in self.sybils and v in self.sybils:
                a["weight"] = self.maximum_weight  # remain together
            elif u in self.sybils or v in self.sybils:
                if self.iteration > 3:
                    if u in [self.target] or v in [self.target]:
                        if a["weight"] > 0:  # victim eradicates
                            a["weight"] -= 2
                    else:
                        if a["weight"] > 0:  # others more slowly
                            a["weight"] -= 1
                else:
                    a["weight"] = self.maximum_weight  # starting value
            elif u in [self.target, self.assist] and \
                 v in [self.target, self.assist]:
                if "weight" in a.keys():
                    if a["weight"] < self.maximum_weight:
                        a["weight"] += 1
                else:
                    a["weight"] = 1
            else:
                a["weight"] = random.randint(1, self.maximum_weight)


ng.Graphs.register_implementation('sybil', SybilNetwork)


class CorruptAuthorityNetwork(ng.NetworkGraph):
    def __init__(self, size, **kwargs):
        self.iteration = 0
        groups = 'a b c trouble'.split(' ')
        num_levels = 3
        g, levels = self._hierarchy_gen(size*num_levels, num_levels)
        self.orig = lambda _: nx.Graph(g)
        self.previous = None
        super().__init__(self.orig, size*levels, delay=True, groups=groups, **kwargs)
        all_nodes = list(self.G)
        self.levels = [[all_nodes[n] for n in level] for level in levels]
        self.problem = self.levels[1][0]
        self._start()

    @property
    def stop(self):
        return self.iteration > 30

    def _node_init(self, n):
        super()._node_init(n)
        for idx, level in enumerate(self.levels):
            if n in level:
                self.G.nodes[n]["group"] = self.groupLabels[idx]
                break

    def _post_init(self):
        super()._post_init()
        self.G.nodes[self.problem]["group"] = self.groupLabels[-1]

    def change(self):
        if self.iteration == 0:
            self.next_change = 10000
        elif self.iteration < 10:  # try/fail to connect to level 1
            if self.previous is not None:
                self.change_type = self.PhaseChange.REMOVE
                self.remove_edge(*self.previous)
                self.previous = None
            else:
                self.change_type = self.PhaseChange.ADD
                edge = (self._random_node(limit_to=self.levels[0]),
                        self._random_node(limit_to=self.levels[1]))
                self.add_edge(*edge)
                self.G[edge[0]][edge[1]]["group"] = 0
                self.G[edge[0]][edge[1]]["weight"] = 3
                self.previous = edge
            self.next_change = 1000
        elif self.iteration < 11:
            if self.previous is not None:
                self.change_type = self.PhaseChange.REMOVE
                self.remove_edge(*self.previous)
            self.next_change = 3000
        elif self.iteration < 15:  # connect to level 2
            self.change_type = self.PhaseChange.ADD
            current = (self._random_node(limit_to=self.levels[0]),
                       self._random_node(limit_to=self.levels[2]))
            self.add_edge(*current)
            self.G[current[0]][current[1]]["group"] = 0
            self.next_change = 3000
        else:
            self.next_change = random.randint(500, 2000)
        self.grouping()
        self.iteration += 1

    def grouping(self):  # noqa
        if not super().grouping():
            return
        problems = []
        for u, v, a in self.G.edges(data=True):
            if (u in self.levels[0] or v in self.levels[0]) and \
                    (u == self.problem or v == self.problem):
                problems.append((u, v))
                if self.iteration < 15:
                    a["weight"] = self.maximum_weight
                else:
                    if a["weight"] > 0:
                        a["weight"] -= 1
            else:
                a["weight"] = random.randint(1, self.maximum_weight)


ng.Graphs.register_implementation('captain', CorruptAuthorityNetwork)
