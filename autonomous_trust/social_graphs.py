import random
import networkx as nx

from . import network_graph as ng


class DeceitNetwork(ng.NetworkGraph):
    def __init__(self, size, **kwargs):
        groups = 'a b c d e f g'.split(' ')
        super().__init__(nx.lollipop_graph, size - 1, 1, groups=groups, **kwargs)

    def change(self):
        pass

    def grouping(self):
        pass


ng.Graphs.register_implementation('lies', DeceitNetwork)


class BetrayalNetwork(ng.NetworkGraph):
    def __init__(self, size, **kwargs):
        groups = 'a b c d e f g'.split(' ')
        super().__init__(nx.lollipop_graph, size - 1, 1, groups=groups, **kwargs)

    def change(self):
        pass

    def grouping(self):
        pass


ng.Graphs.register_implementation('frenemy', BetrayalNetwork)


class ReputationManipulationNetwork(ng.NetworkGraph):
    def __init__(self, size, **kwargs):
        groups = 'a b c d e f g'.split(' ')
        super().__init__(nx.lollipop_graph, size - 1, 1, groups=groups, **kwargs)

    def change(self):
        pass

    def grouping(self):
        pass


ng.Graphs.register_implementation('clique', ReputationManipulationNetwork)


class SybilNetwork(ng.NetworkGraph):
    def __init__(self, size, **kwargs):
        self.sybils = list(range(size - 2))  # indices
        self.victim = size - 2  # index
        self.assist = size - 1  # index
        self.iteration = 0
        groups = 'a b c d e f g'.split(' ')
        super().__init__(nx.lollipop_graph, size - 1, 1, groups=groups, **kwargs)

    def _sybil_neighbors(self, n):
        if n in self.sybils + [self.victim]:
            return []
        neighbors = list(self.G.neighbors(n))
        sybil_list = []
        for nbr in neighbors:
            if nbr in self.sybils:
                sybil_list.append(nbr)
        return sybil_list

    def node_removal_rejected(self, n):
        return n in self.sybils

    def link_addition_limit(self):
        node_list = []
        for n in self.G:
            if len(list(self.G.neighbors(n))) == 0:
                node_list.append(n)
        return node_list

    def link_addition_rejected(self, u, v):
        for n in [u, v]:
            neighbors = list(self.G.neighbors(n))
            sybils = self._sybil_neighbors(n)
            if len(sybils) > 0 and len(sybils) >= len(neighbors):
                self.remove_edge(n, sybils[-1])

    def link_removal_rejected(self, u, v):
        return u in self.sybils and v in self.sybils
        
    def change(self):
        self.change_type = self.PhaseChange.META
        if self.iteration == 0:
            self.next_change = 2000
        elif self.iteration == 1:
            self.next_change = 2000
        else:
            self.random_change()
        self.next_change = random.randint(1, 500)
        self.grouping()
        self.iteration += 1

    def grouping(self):
        if self.iteration == 0:
            for n in self.G:
                self.G.nodes[n]["name"] = n
                self.G.nodes[n]["group"] = self.groups_len
            self.G.nodes[self.victim]["group"] = self.groups_len - 1
        elif self.iteration == 1:
            self.G.nodes[self.assist]["name"] = self.assist
            self.G.nodes[self.assist]["group"] = self.groups_len - 2
        else:
            for n in self.G:
                if n > self.assist:
                    self.G.nodes[n]["name"] = n
                    self.G.nodes[n]["group"] = random.randint(1, self.groups_len - 3)
                    
        for u, v, a in self.G.edges(data=True):
            src = self.G.nodes[u]
            tgt = self.G.nodes[v]
            if "group" in src.keys() and "group" in tgt.keys():
                a["group"] = src["group"] if src["group"] == tgt["group"] else 0
            if u in self.sybils and v in self.sybils:
                a["value"] = 10  # remain together
            elif u in self.sybils or v in self.sybils:
                if "value" in a.keys():
                    if u in [self.victim] or v in [self.victim]:
                        if a["value"] > 0:  # victim eradicates
                            a["value"] -= 1
                    else:
                        if a["value"] > 1:  # others minimize
                            a["value"] -= 1
                else:
                    a["value"] = 10  # starting value
            elif u in [self.victim, self.assist] and \
                 v in [self.victim, self.assist]:
                if "value" in a.keys():
                    if a["value"] < 12:
                        a["value"] += 1
                else:
                    a["value"] = 1
            else:
                a["value"] = random.randint(1, 8)


ng.Graphs.register_implementation('sybil', SybilNetwork)


class CorruptAuthorityNetwork(ng.NetworkGraph):
    def __init__(self, size, **kwargs):
        groups = 'a b c d e f g'.split(' ')
        super().__init__(nx.lollipop_graph, size - 1, 1, groups=groups, **kwargs)

    def change(self):
        pass

    def grouping(self):
        pass


ng.Graphs.register_implementation('captain', CorruptAuthorityNetwork)
